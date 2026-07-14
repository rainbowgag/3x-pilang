#!/usr/bin/env python3
import argparse
import json
import os
import random
import shutil
import sqlite3
import ssl
import string
import subprocess
import sys
import time
import uuid
import zipfile
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from pathlib import Path
from urllib import parse, request


DEFAULT_DB = "/etc/x-ui/x-ui.db"
DEFAULT_PRIVATE_KEY = "QLc4ia17FIhB9Vc_4yi2vpPxZoNJQLqODzJsOlQS_1M"
DEFAULT_PUBLIC_KEY = "8Km22wZcpKxURKU_BLZA5bWcPbe7u8hvEobI8vrymTE"
DEFAULT_SHORT_IDS = "abc5,64d48d3026a71bee,de,1dc6dcb758f649,da7fab,dea3c367a8,4b4370dc,7ec0d3e8484d"
DOWNLOADS = {}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Batch add 3x-ui inbounds, socks outbounds, and routing rules."
    )
    parser.add_argument("--panel-url", help="3x-ui panel base URL, e.g. https://host:8443/basepath")
    parser.add_argument("--username", help="3x-ui username")
    parser.add_argument("--password", help="3x-ui password")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"3x-ui SQLite db path, default: {DEFAULT_DB}")
    parser.add_argument("--name-prefix", help="Outbound/inbound remark prefix, e.g. 德国z")
    parser.add_argument("--name-start", type=int, default=1, help="Name start index, default: 1")
    parser.add_argument("--inbound-start-port", type=int, help="Inbound start port, e.g. 11111")
    parser.add_argument("--input-file", help="Text file containing one proxy per line. If omitted, read stdin.")
    parser.add_argument("--use-api", action="store_true", help="Create inbounds through panel API instead of direct SQLite insert")
    parser.add_argument("--insecure", action="store_true", help="Skip HTTPS certificate verification")
    parser.add_argument("--restart-xui", action="store_true", help="Restart x-ui service after db update")
    parser.add_argument("--dry-run", action="store_true", help="Print planned changes without writing")
    parser.add_argument("--web", action="store_true", help="Start a local web UI")
    parser.add_argument("--web-host", default="127.0.0.1", help="Web UI bind host, default: 127.0.0.1")
    parser.add_argument("--web-port", type=int, default=8765, help="Web UI port, default: 8765")
    parser.add_argument("--share-host", help="Public node host/IP used for generated VLESS links and QR images")
    parser.add_argument("--qr-output-dir", default="/root/xui-qr-zips", help="Directory for generated QR zip files")
    parser.add_argument("--reality-private-key", default=DEFAULT_PRIVATE_KEY)
    parser.add_argument("--reality-public-key", default=DEFAULT_PUBLIC_KEY)
    parser.add_argument("--reality-target", default="www.sony.com:443")
    parser.add_argument("--reality-sni", default="www.sony.com")
    parser.add_argument("--reality-short-ids", default=DEFAULT_SHORT_IDS)
    parser.add_argument("--fingerprint", default="chrome")
    parser.add_argument("--spider-x", default="/")
    return parser.parse_args()


def clean_line(line):
    line = line.strip()
    if line.endswith("}") and "{" in line:
        line = line[: line.rfind("{")].strip()
    return line


def parse_proxy_lines(text):
    nodes = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = clean_line(raw)
        if not line:
            continue

        if "@" in line:
            auth, server = line.rsplit("@", 1)
            auth_parts = auth.split(":")
            server_parts = server.rsplit(":", 1)
            if len(auth_parts) < 2 or len(server_parts) != 2:
                raise ValueError(f"line {line_no}: expected user:pass@ip:port, got {raw!r}")
            user = auth_parts[0]
            password = ":".join(auth_parts[1:])
            address, port_text = server_parts
        else:
            parts = line.split(":")
            if len(parts) < 4:
                raise ValueError(f"line {line_no}: expected ip:port:user:pass or user:pass@ip:port, got {raw!r}")
            address, port_text, user = parts[:3]
            password = ":".join(parts[3:])

        port = int(port_text)
        if not (1 <= port <= 65535):
            raise ValueError(f"line {line_no}: invalid port {port}")
        nodes.append(
            {
                "address": address.strip(),
                "port": port,
                "user": user.strip(),
                "pass": password.strip(),
            }
        )
    if not nodes:
        raise ValueError("no valid socks nodes found")
    return nodes


def rand_text(length):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def build_socks_outbound(tag, node):
    return {
        "tag": tag,
        "protocol": "socks",
        "settings": {
            "servers": [
                {
                    "address": node["address"],
                    "port": node["port"],
                    "users": [
                        {
                            "user": node["user"],
                            "pass": node["pass"],
                        }
                    ],
                }
            ]
        },
    }


def build_route(inbound_tag, outbound_tag):
    return {
        "type": "field",
        "inboundTag": [inbound_tag],
        "outboundTag": outbound_tag,
    }


def build_inbound_payload(args, remark, inbound_port, inbound_tag):
    client_id = str(uuid.uuid4())
    email = rand_text(10)
    now = int(time.time() * 1000)
    sub_id = rand_text(16)
    settings = {
        "clients": [
            {
                "auth": rand_text(16),
                "comment": remark,
                "created_at": now,
                "id": client_id,
                "email": email,
                "enable": True,
                "expiryTime": 0,
                "flow": "",
                "limitIp": 0,
                "password": rand_text(16),
                "reset": 0,
                "security": "auto",
                "subId": sub_id,
                "tgId": 0,
                "totalGB": 0,
                "updated_at": now,
            }
        ],
        "decryption": "none",
        "encryption": "none",
    }
    short_ids = [item.strip() for item in args.reality_short_ids.split(",") if item.strip()]
    stream_settings = {
        "network": "tcp",
        "security": "reality",
        "tcpSettings": {
            "acceptProxyProtocol": False,
            "header": {"type": "none"},
        },
        "realitySettings": {
            "show": False,
            "xver": 0,
            "target": args.reality_target,
            "serverNames": [args.reality_sni],
            "privateKey": args.reality_private_key,
            "minClientVer": "",
            "maxClientVer": "",
            "maxTimediff": 0,
            "shortIds": short_ids,
            "mldsa65Seed": "",
            "settings": {
                "publicKey": args.reality_public_key,
                "fingerprint": args.fingerprint,
                "serverName": "",
                "spiderX": args.spider_x,
                "mldsa65Verify": "",
            },
        },
    }
    sniffing = {"enabled": False, "destOverride": ["http", "tls", "quic", "fakedns"]}
    return {
        "userId": 1,
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": remark,
        "enable": True,
        "expiryTime": 0,
        "listen": "",
        "port": inbound_port,
        "protocol": "vless",
        "settings": json.dumps(settings, separators=(",", ":")),
        "streamSettings": json.dumps(stream_settings, separators=(",", ":")),
        "sniffing": json.dumps(sniffing, separators=(",", ":")),
        "tag": inbound_tag,
    }


class PanelClient:
    def __init__(self, base_url, username, password, insecure=False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.cookies = CookieJar()
        handlers = [request.HTTPCookieProcessor(self.cookies)]
        if insecure:
            handlers.append(request.HTTPSHandler(context=ssl._create_unverified_context()))
        self.opener = request.build_opener(*handlers)

    def _url(self, path):
        return self.base_url + path

    def post_form(self, path, data):
        body = parse.urlencode(data).encode()
        req = request.Request(
            self._url(path),
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with self.opener.open(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def post_json(self, path, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        req = request.Request(
            self._url(path),
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def login(self):
        # 3x-ui commonly accepts username/password at /login.
        resp = self.post_form("/login", {"username": self.username, "password": self.password})
        try:
            data = json.loads(resp)
            if data.get("success") is False:
                raise RuntimeError(f"login failed: {data}")
        except json.JSONDecodeError:
            if "login" in resp.lower() and "password" in resp.lower():
                raise RuntimeError("login may have failed; received login page again")

    def add_inbound(self, payload):
        resp = self.post_json("/panel/api/inbounds/add", payload)
        try:
            data = json.loads(resp)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"add inbound returned non-json: {resp[:300]}") from exc
        if data.get("success") is False:
            raise RuntimeError(f"add inbound failed: {data}")
        return data


def backup_db(db_path):
    src = Path(db_path)
    if not src.exists():
        raise FileNotFoundError(f"db not found: {db_path}")
    backup_dir = Path("/root/xui-batch-backups")
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = backup_dir / f"x-ui.db.{stamp}.bak"
    shutil.copy2(src, backup)
    return backup


def update_template_config(db_path, outbounds_to_add, routes_to_add):
    conn = sqlite3.connect(db_path)
    try:
        added_outbounds, added_routes = update_template_config_conn(
            conn, outbounds_to_add, routes_to_add
        )
        conn.commit()
        return added_outbounds, added_routes
    finally:
        conn.close()


def update_template_config_conn(conn, outbounds_to_add, routes_to_add):
    row = conn.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
    if not row:
        raise RuntimeError("settings.xrayTemplateConfig not found")
    config = json.loads(row[0])
    config.setdefault("outbounds", [])
    config.setdefault("routing", {}).setdefault("rules", [])

    outbounds = config["outbounds"]
    rules = config["routing"]["rules"]
    existing_outbound_tags = {item.get("tag") for item in outbounds}
    existing_route_keys = {
        (tuple(item.get("inboundTag") or []), item.get("outboundTag"))
        for item in rules
    }

    added_outbounds = 0
    for outbound in outbounds_to_add:
        if outbound["tag"] not in existing_outbound_tags:
            outbounds.append(outbound)
            existing_outbound_tags.add(outbound["tag"])
            added_outbounds += 1

    added_routes = 0
    for rule in routes_to_add:
        key = (tuple(rule.get("inboundTag") or []), rule.get("outboundTag"))
        if key not in existing_route_keys:
            rules.append(rule)
            existing_route_keys.add(key)
            added_routes += 1

    text = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    conn.execute("update settings set value=? where key='xrayTemplateConfig'", (text,))
    return added_outbounds, added_routes


def value_for_inbound_column(column, payload, index):
    now = int(time.time() * 1000)
    mapping = {
        "user_id": "userId",
        "userid": "userId",
        "expiry_time": "expiryTime",
        "expirytime": "expiryTime",
        "traffic_reset": "trafficReset",
        "trafficreset": "trafficReset",
        "last_traffic_reset_time": "lastTrafficResetTime",
        "lasttrafficresettime": "lastTrafficResetTime",
        "stream_settings": "streamSettings",
        "streamsettings": "streamSettings",
        "node_id": "nodeId",
        "nodeid": "nodeId",
        "share_addr_strategy": "shareAddrStrategy",
        "shareaddrstrategy": "shareAddrStrategy",
        "share_addr": "shareAddr",
        "shareaddr": "shareAddr",
        "sub_sort_index": "subSortIndex",
        "subsortindex": "subSortIndex",
        "origin_node_guid": "originNodeGuid",
        "originnodeguid": "originNodeGuid",
        "fallback_parent": "fallbackParent",
        "fallbackparent": "fallbackParent",
        "created_at": "created_at",
        "updated_at": "updated_at",
        "last_traffic_reset_time": "lastTrafficResetTime",
    }
    normalized = column.lower()
    source = mapping.get(normalized, column)
    defaults = {
        "userId": 1,
        "up": 0,
        "down": 0,
        "total": 0,
        "enable": True,
        "expiryTime": 0,
        "trafficReset": "never",
        "lastTrafficResetTime": 0,
        "listen": "",
        "nodeId": None,
        "shareAddrStrategy": "listen",
        "shareAddr": "",
        "subSortIndex": index + 1,
        "originNodeGuid": "",
        "fallbackParent": None,
        "created_at": now,
        "updated_at": now,
    }
    if source in payload:
        return payload[source]
    if source in defaults:
        return defaults[source]
    return None


def add_client_record(conn, inbound_id, payload):
    settings = json.loads(payload["settings"])
    clients = settings.get("clients") or []
    now = int(time.time() * 1000)

    for client in clients:
        email = client.get("email")
        if not email:
            continue

        existing = conn.execute("select id from clients where email=?", (email,)).fetchone()
        if existing:
            client_id = existing[0]
        else:
            cursor = conn.execute(
                """
                insert into clients (
                    email, sub_id, uuid, password, auth, flow, security, reverse,
                    limit_ip, total_gb, expiry_time, enable, tg_id, group_name,
                    comment, reset, created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    client.get("subId", ""),
                    client.get("id", ""),
                    client.get("password", ""),
                    client.get("auth", ""),
                    client.get("flow", ""),
                    client.get("security", "auto"),
                    "",
                    int(client.get("limitIp") or 0),
                    int(client.get("totalGB") or 0),
                    int(client.get("expiryTime") or 0),
                    bool(client.get("enable", True)),
                    int(client.get("tgId") or 0),
                    "",
                    client.get("comment") or payload.get("remark") or "",
                    int(client.get("reset") or 0),
                    int(client.get("created_at") or now),
                    int(client.get("updated_at") or now),
                ),
            )
            client_id = cursor.lastrowid

        conn.execute(
            """
            insert or ignore into client_inbounds
                (client_id, inbound_id, flow_override, created_at)
            values (?, ?, ?, ?)
            """,
            (client_id, inbound_id, client.get("flow", ""), now),
        )


def add_inbounds_to_db(db_path, planned):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        added, skipped = add_inbounds_to_db_conn(conn, planned)
        conn.commit()
        return added, skipped
    finally:
        conn.close()


def add_inbounds_to_db_conn(conn, planned):
    table_info = conn.execute("pragma table_info(inbounds)").fetchall()
    if not table_info:
        raise RuntimeError("inbounds table not found")

    columns = [row[1] for row in table_info]
    insertable = [col for col in columns if col.lower() != "id"]
    existing_by_port = {
        row["port"]: row
        for row in conn.execute("select id, remark, port, tag, settings from inbounds").fetchall()
    }
    existing_by_tag = {
        row["tag"]: row
        for row in conn.execute("select id, remark, port, tag, settings from inbounds").fetchall()
    }

    added = 0
    skipped = 0
    for index, item in enumerate(planned):
        payload = item["inbound_payload"]
        port_row = existing_by_port.get(payload["port"])
        tag_row = existing_by_tag.get(payload["tag"])

        if port_row or tag_row:
            row = port_row or tag_row
            if row["port"] != payload["port"] or row["tag"] != payload["tag"]:
                raise RuntimeError(
                    f"inbound conflict: port {payload['port']} or tag {payload['tag']} already used by {row['tag']}:{row['port']}"
                )
            existing_payload = {
                "settings": row["settings"],
                "remark": row["remark"],
            }
            add_client_record(conn, row["id"], existing_payload)
            skipped += 1
            continue

        values = [value_for_inbound_column(col, payload, index) for col in insertable]
        placeholders = ",".join("?" for _ in insertable)
        quoted_cols = ",".join(f"`{col}`" for col in insertable)
        cursor = conn.execute(
            f"insert into inbounds ({quoted_cols}) values ({placeholders})",
            values,
        )
        add_client_record(conn, cursor.lastrowid, payload)
        new_row = {
            "id": cursor.lastrowid,
            "remark": payload["remark"],
            "port": payload["port"],
            "tag": payload["tag"],
            "settings": payload["settings"],
        }
        existing_by_port[payload["port"]] = new_row
        existing_by_tag[payload["tag"]] = new_row
        added += 1

    return added, skipped


def apply_batch_to_db(db_path, planned):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("begin")
        added_inbounds, skipped_inbounds = add_inbounds_to_db_conn(conn, planned)
        added_outbounds, added_routes = update_template_config_conn(
            conn,
            [item["outbound"] for item in planned],
            [item["route"] for item in planned],
        )
        conn.commit()
        return added_inbounds, skipped_inbounds, added_outbounds, added_routes
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def verify_batch_in_db(db_path, planned):
    conn = sqlite3.connect(db_path)
    try:
        inbound_tags = {
            row[0] for row in conn.execute("select tag from inbounds").fetchall()
        }
        row = conn.execute("select value from settings where key='xrayTemplateConfig'").fetchone()
        if not row:
            raise RuntimeError("settings.xrayTemplateConfig not found after write")
        config = json.loads(row[0])
        outbound_tags = {item.get("tag") for item in config.get("outbounds", [])}
        route_keys = {
            (tuple(item.get("inboundTag") or []), item.get("outboundTag"))
            for item in config.get("routing", {}).get("rules", [])
        }

        missing = []
        for item in planned:
            if item["inbound_tag"] not in inbound_tags:
                missing.append(f"inbound {item['inbound_tag']}")
            if item["remark"] not in outbound_tags:
                missing.append(f"outbound {item['remark']}")
            route_key = ((item["inbound_tag"],), item["remark"])
            if route_key not in route_keys:
                missing.append(f"route {item['inbound_tag']} -> {item['remark']}")

        if missing:
            raise RuntimeError("write verification failed: " + ", ".join(missing))
        return True
    finally:
        conn.close()


def normalize_share_host(value):
    value = (value or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = parse.urlsplit(value)
        value = parsed.hostname or value
    value = value.strip().strip("/")
    if ":" in value and not value.startswith("["):
        # Keep IPv6 usable in URLs.
        if value.count(":") > 1:
            value = f"[{value}]"
    return value


def build_vless_link(item, args):
    host = normalize_share_host(getattr(args, "share_host", ""))
    if not host:
        return ""

    settings = json.loads(item["inbound_payload"]["settings"])
    client = settings["clients"][0]
    short_ids = [part.strip() for part in args.reality_short_ids.split(",") if part.strip()]
    query = {
        "type": "tcp",
        "security": "reality",
        "pbk": args.reality_public_key,
        "fp": args.fingerprint,
        "sni": args.reality_sni,
        "sid": short_ids[0] if short_ids else "",
        "spx": args.spider_x,
    }
    return (
        f"vless://{client['id']}@{host}:{item['inbound_port']}"
        f"?{parse.urlencode(query)}"
        f"#{parse.quote(item['remark'])}"
    )


def safe_filename(value):
    allowed = set(string.ascii_letters + string.digits + "._-")
    cleaned = "".join(ch if ch in allowed else "_" for ch in value)
    return cleaned.strip("._") or "node"


def generate_qr_zip(planned, args):
    links = [(item["remark"], build_vless_link(item, args)) for item in planned]
    links = [(remark, link) for remark, link in links if link]
    if not links:
        return None

    try:
        import qrcode
    except ImportError as exc:
        raise RuntimeError("QR generation requires qrcode. Install it with: apt install -y python3-qrcode python3-pil") from exc

    output_dir = Path(args.qr_output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    zip_path = output_dir / f"3xui-qrcodes-{stamp}.zip"

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        link_text = []
        for remark, link in links:
            name = safe_filename(remark)
            img = qrcode.make(link)
            png_path = output_dir / f"{name}.png"
            img.save(png_path)
            zf.write(png_path, f"{name}.png")
            png_path.unlink(missing_ok=True)
            link_text.append(f"{remark}\n{link}\n")
        zf.writestr("links.txt", "\n".join(link_text))

    return str(zip_path)


def plan_nodes(args, text):
    nodes = parse_proxy_lines(text)
    planned = []
    for idx, node in enumerate(nodes):
        number = args.name_start + idx
        remark = f"{args.name_prefix}{number}"
        inbound_port = args.inbound_start_port + idx
        if inbound_port > 65535:
            raise ValueError("inbound port exceeds 65535")
        inbound_tag = f"in-{inbound_port}-tcp"
        planned.append(
            {
                "remark": remark,
                "inbound_port": inbound_port,
                "inbound_tag": inbound_tag,
                "inbound_payload": build_inbound_payload(args, remark, inbound_port, inbound_tag),
                "outbound": build_socks_outbound(remark, node),
                "route": build_route(inbound_tag, remark),
            }
        )
    return planned


def run_batch(args, text, emit=print):
    planned = plan_nodes(args, text)

    emit(f"Planned nodes: {len(planned)}")
    for item in planned:
        emit(f"- {item['remark']}: inbound {item['inbound_tag']}, outbound {item['outbound']['settings']['servers'][0]['address']}:{item['outbound']['settings']['servers'][0]['port']}")

    if args.dry_run:
        emit("\nDry run only. No changes written.")
        return {"planned": len(planned), "dry_run": True}

    backup = backup_db(args.db)
    emit(f"\nDB backup: {backup}")

    if args.use_api:
        client = PanelClient(args.panel_url, args.username, args.password, args.insecure)
        client.login()
        emit("Panel login: ok")

        for item in planned:
            client.add_inbound(item["inbound_payload"])
            emit(f"Added inbound via API: {item['remark']} / {item['inbound_tag']}")
        added_inbounds = len(planned)
        skipped_inbounds = 0
        added_outbounds, added_routes = update_template_config(
            args.db,
            [item["outbound"] for item in planned],
            [item["route"] for item in planned],
        )
    else:
        added_inbounds, skipped_inbounds, added_outbounds, added_routes = apply_batch_to_db(
            args.db, planned
        )
        emit(f"Added inbounds to database: {added_inbounds}")
        if skipped_inbounds:
            emit(f"Skipped existing inbounds and repaired client links: {skipped_inbounds}")
    emit(f"Added outbounds to xrayTemplateConfig: {added_outbounds}")
    emit(f"Added routing rules to xrayTemplateConfig: {added_routes}")
    verify_batch_in_db(args.db, planned)
    emit("Verified database: inbounds, outbounds, and routing rules are present")

    if args.restart_xui:
        subprocess.run(["systemctl", "restart", "x-ui"], check=True)
        emit("Restarted x-ui service")
    else:
        emit("Done. Restart Xray/x-ui from panel, or rerun with --restart-xui.")

    qr_zip = None
    if normalize_share_host(getattr(args, "share_host", "")):
        qr_zip = generate_qr_zip(planned, args)
        emit(f"Generated QR zip: {qr_zip}")

    return {
        "planned": len(planned),
        "backup": str(backup),
        "added_inbounds": added_inbounds,
        "skipped_inbounds": skipped_inbounds,
        "added_outbounds": added_outbounds,
        "added_routes": added_routes,
        "qr_zip": qr_zip,
    }


WEB_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>3x-ui 批量节点创建</title>
  <style>
    body{margin:0;background:#f5f7fb;color:#1f2937;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
    main{width:min(1100px,calc(100% - 28px));margin:0 auto;padding:24px 0 36px}
    h1{font-size:26px;margin:0 0 6px}.sub{color:#667085;margin:0 0 18px}
    form{display:grid;grid-template-columns:1fr 1fr;gap:14px;background:white;border:1px solid #d8dee8;border-radius:8px;padding:16px;box-shadow:0 10px 30px rgba(17,24,39,.06)}
    label{display:block;font-weight:700;font-size:13px;margin-bottom:7px;color:#344054}
    input,textarea{width:100%;box-sizing:border-box;border:1px solid #d8dee8;border-radius:8px;padding:10px 12px;font:inherit;background:white}
    textarea{min-height:260px;font-family:Consolas,monospace;font-size:13px;line-height:1.5;resize:vertical}
    .full{grid-column:1/-1}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.checks{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.checks label{margin:0;font-weight:600}
    button{height:42px;border:0;border-radius:8px;background:#0f766e;color:white;font-weight:800;padding:0 18px;cursor:pointer}.hint{font-size:12px;color:#667085;margin-top:6px}
    pre{white-space:pre-wrap;background:#111827;color:#e5e7eb;border-radius:8px;padding:14px;min-height:180px;overflow:auto}
    @media(max-width:760px){form,.row{grid-template-columns:1fr}}
  </style>
</head>
<body>
<main>
  <h1>3x-ui 批量节点创建</h1>
  <p class="sub">粘贴 socks 节点后直接写入本机 3x-ui 数据库，自动创建入站、追加 socks 出站和路由规则。提交前会自动备份数据库。</p>
  <form method="post" action="/run">
    <div class="full">
      <label>socks 节点列表</label>
      <textarea name="nodes" required placeholder="82.198.243.27:443:user:pass{宏}&#10;user:pass@82.198.243.27:443"></textarea>
      <div class="hint">支持两种格式：IP:端口:用户名:密码，或 用户名:密码@IP:端口；行尾 {宏} 会自动忽略。</div>
    </div>
    <div>
      <label>面板地址</label>
      <input name="panel_url" placeholder="仅 API 模式需要，例如 https://yy.yaml.uk:8443/面板路径">
    </div>
    <div class="row">
      <div><label>账号</label><input name="username" placeholder="仅 API 模式需要"></div>
      <div><label>密码</label><input name="password" type="password" placeholder="仅 API 模式需要"></div>
    </div>
    <div class="row">
      <div><label>节点名前缀</label><input name="name_prefix" required value="德国z"></div>
      <div><label>名称起始编号</label><input name="name_start" type="number" value="1"></div>
    </div>
    <div class="row">
      <div><label>节点连接地址</label><input name="share_host" placeholder="用于二维码，例如 d.yaml.uk 或 149.104.110.70"></div>
      <div><label>二维码输出目录</label><input name="qr_output_dir" value="/root/xui-qr-zips"></div>
    </div>
    <div class="row">
      <div><label>入站起始端口</label><input name="inbound_start_port" type="number" required value="11111"></div>
      <div><label>数据库路径</label><input name="db" value="/etc/x-ui/x-ui.db"></div>
    </div>
    <div class="row">
      <div><label>Reality 私钥</label><input name="reality_private_key" value="__PRIVATE_KEY__"></div>
      <div><label>Reality 公钥</label><input name="reality_public_key" value="__PUBLIC_KEY__"></div>
    </div>
    <div class="row">
      <div><label>Reality 目标</label><input name="reality_target" value="www.sony.com:443"></div>
      <div><label>Reality SNI</label><input name="reality_sni" value="www.sony.com"></div>
    </div>
    <div class="full"><label>shortIds</label><input name="reality_short_ids" value="__SHORT_IDS__"></div>
    <div class="checks full">
      <label><input type="checkbox" name="insecure" checked> 跳过 HTTPS 证书校验</label>
      <label><input type="checkbox" name="restart_xui" checked> 完成后重启 x-ui</label>
      <label><input type="checkbox" name="dry_run"> 只演练不写入</label>
      <label><input type="checkbox" name="use_api"> 使用面板 API 创建入站</label>
    </div>
    <div class="full"><button type="submit">开始创建</button></div>
  </form>
  <h2>执行结果</h2>
  <pre>提交后这里会显示结果。</pre>
</main>
</body>
</html>""".replace("__PRIVATE_KEY__", DEFAULT_PRIVATE_KEY).replace("__PUBLIC_KEY__", DEFAULT_PUBLIC_KEY).replace("__SHORT_IDS__", DEFAULT_SHORT_IDS)


def html_escape(text):
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def web_args_from_form(form):
    def field(name, default=""):
        return form.get(name, [default])[0]

    def int_field(name, default):
        value = field(name, str(default)).strip()
        return int(value or default)

    return SimpleNamespace(
        panel_url=field("panel_url").strip(),
        username=field("username").strip(),
        password=field("password"),
        db=field("db", DEFAULT_DB).strip() or DEFAULT_DB,
        name_prefix=field("name_prefix").strip(),
        name_start=int_field("name_start", 1),
        inbound_start_port=int_field("inbound_start_port", 11111),
        input_file=None,
        use_api="use_api" in form,
        insecure="insecure" in form,
        restart_xui="restart_xui" in form,
        dry_run="dry_run" in form,
        reality_private_key=field("reality_private_key", DEFAULT_PRIVATE_KEY).strip(),
        reality_public_key=field("reality_public_key", DEFAULT_PUBLIC_KEY).strip(),
        reality_target=field("reality_target", "www.sony.com:443").strip(),
        reality_sni=field("reality_sni", "www.sony.com").strip(),
        reality_short_ids=field("reality_short_ids", DEFAULT_SHORT_IDS).strip(),
        share_host=field("share_host", "").strip(),
        qr_output_dir=field("qr_output_dir", "/root/xui-qr-zips").strip() or "/root/xui-qr-zips",
        fingerprint="chrome",
        spider_x="/",
    )


class BatchWebHandler(BaseHTTPRequestHandler):
    def send_html(self, body, status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/download/"):
            name = parse.unquote(self.path.split("/download/", 1)[1])
            path = DOWNLOADS.get(Path(name).name) or (Path("/root/xui-qr-zips") / Path(name).name)
            path = Path(path)
            if not path.exists() or path.suffix != ".zip":
                self.send_html("Not found", 404)
                return
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{path.name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path not in ("/", "/run"):
            self.send_html("Not found", 404)
            return
        self.send_html(WEB_HTML)

    def do_POST(self):
        if self.path != "/run":
            self.send_html("Not found", 404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse.parse_qs(raw, keep_blank_values=True)
        output = []
        result_data = {}
        try:
            args = web_args_from_form(form)
            nodes = form.get("nodes", [""])[0]
            result_data = run_batch(args, nodes, emit=output.append)
        except Exception as exc:
            output.append(f"ERROR: {exc}")
        result = "\n".join(output)
        escaped = html_escape(result)
        qr_zip = result_data.get("qr_zip") if isinstance(result_data, dict) else None
        if qr_zip:
            name = Path(qr_zip).name
            DOWNLOADS[name] = qr_zip
            escaped += f'\n\n<a style="color:#93c5fd" href="/download/{parse.quote(name)}">下载二维码 ZIP：{html_escape(name)}</a>'
        page = WEB_HTML.replace("提交后这里会显示结果。", escaped)
        self.send_html(page)

    def log_message(self, fmt, *args):
        print(f"[web] {self.address_string()} - {fmt % args}")


def start_web(args):
    server = HTTPServer((args.web_host, args.web_port), BatchWebHandler)
    print(f"Web UI running at http://{args.web_host}:{args.web_port}")
    print("Keep this terminal open. Press Ctrl-C to stop.")
    server.serve_forever()


def main():
    args = parse_args()
    if args.web:
        start_web(args)
        return

    required = ["name_prefix", "inbound_start_port"]
    if args.use_api:
        required.extend(["panel_url", "username", "password"])
    missing = [name for name in required if not getattr(args, name)]
    if missing:
        raise ValueError("missing required arguments for CLI mode: " + ", ".join(f"--{name.replace('_', '-')}" for name in missing))

    if args.input_file:
        text = Path(args.input_file).read_text(encoding="utf-8")
    else:
        print("Paste socks nodes, then press Ctrl-D:", file=sys.stderr)
        text = sys.stdin.read()

    run_batch(args, text)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
