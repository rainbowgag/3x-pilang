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
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from pathlib import Path
from urllib import parse, request


DEFAULT_DB = "/etc/x-ui/x-ui.db"
DEFAULT_PRIVATE_KEY = "QLc4ia17FIhB9Vc_4yi2vpPxZoNJQLqODzJsOlQS_1M"
DEFAULT_PUBLIC_KEY = "8Km22wZcpKxURKU_BLZA5bWcPbe7u8hvEobI8vrymTE"
DEFAULT_SHORT_IDS = "abc5,64d48d3026a71bee,de,1dc6dcb758f649,da7fab,dea3c367a8,4b4370dc,7ec0d3e8484d"


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
    parser.add_argument("--insecure", action="store_true", help="Skip HTTPS certificate verification")
    parser.add_argument("--restart-xui", action="store_true", help="Restart x-ui service after db update")
    parser.add_argument("--dry-run", action="store_true", help="Print planned changes without writing")
    parser.add_argument("--web", action="store_true", help="Start a local web UI")
    parser.add_argument("--web-host", default="127.0.0.1", help="Web UI bind host, default: 127.0.0.1")
    parser.add_argument("--web-port", type=int, default=8765, help="Web UI port, default: 8765")
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
        parts = line.split(":")
        if len(parts) < 4:
            raise ValueError(f"line {line_no}: expected ip:port:user:pass, got {raw!r}")
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
    settings = {
        "clients": [
            {
                "id": client_id,
                "email": email,
                "enable": True,
                "expiryTime": 0,
                "flow": "",
                "limitIp": 0,
                "subId": rand_text(16),
                "tgId": "",
                "totalGB": 0,
                "reset": 0,
            }
        ],
        "decryption": "none",
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
        self.opener = request.build_opener(request.HTTPCookieProcessor(self.cookies))
        self.context = ssl._create_unverified_context() if insecure else None

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
        with self.opener.open(req, context=self.context, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")

    def post_json(self, path, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        req = request.Request(
            self._url(path),
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.opener.open(req, context=self.context, timeout=30) as resp:
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
        conn.commit()
        return added_outbounds, added_routes
    finally:
        conn.close()


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

    client = PanelClient(args.panel_url, args.username, args.password, args.insecure)
    client.login()
    emit("Panel login: ok")

    for item in planned:
        client.add_inbound(item["inbound_payload"])
        emit(f"Added inbound: {item['remark']} / {item['inbound_tag']}")

    added_outbounds, added_routes = update_template_config(
        args.db,
        [item["outbound"] for item in planned],
        [item["route"] for item in planned],
    )
    emit(f"Added outbounds to xrayTemplateConfig: {added_outbounds}")
    emit(f"Added routing rules to xrayTemplateConfig: {added_routes}")

    if args.restart_xui:
        subprocess.run(["systemctl", "restart", "x-ui"], check=True)
        emit("Restarted x-ui service")
    else:
        emit("Done. Restart Xray/x-ui from panel, or rerun with --restart-xui.")

    return {
        "planned": len(planned),
        "backup": str(backup),
        "added_outbounds": added_outbounds,
        "added_routes": added_routes,
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
  <p class="sub">粘贴 socks 节点后自动创建入站、追加 socks 出站和路由规则。提交前会自动备份数据库。</p>
  <form method="post" action="/run">
    <div class="full">
      <label>socks 节点列表</label>
      <textarea name="nodes" required placeholder="82.198.243.27:443:user:pass{宏}"></textarea>
      <div class="hint">每行格式：IP:端口:用户名:密码，行尾 {宏} 会自动忽略。</div>
    </div>
    <div>
      <label>面板地址</label>
      <input name="panel_url" required placeholder="https://yy.yaml.uk:8443/面板路径">
    </div>
    <div class="row">
      <div><label>账号</label><input name="username" required></div>
      <div><label>密码</label><input name="password" type="password" required></div>
    </div>
    <div class="row">
      <div><label>节点名前缀</label><input name="name_prefix" required value="德国z"></div>
      <div><label>名称起始编号</label><input name="name_start" type="number" value="1"></div>
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
        insecure="insecure" in form,
        restart_xui="restart_xui" in form,
        dry_run="dry_run" in form,
        reality_private_key=field("reality_private_key", DEFAULT_PRIVATE_KEY).strip(),
        reality_public_key=field("reality_public_key", DEFAULT_PUBLIC_KEY).strip(),
        reality_target=field("reality_target", "www.sony.com:443").strip(),
        reality_sni=field("reality_sni", "www.sony.com").strip(),
        reality_short_ids=field("reality_short_ids", DEFAULT_SHORT_IDS).strip(),
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
        try:
            args = web_args_from_form(form)
            nodes = form.get("nodes", [""])[0]
            run_batch(args, nodes, emit=output.append)
        except Exception as exc:
            output.append(f"ERROR: {exc}")
        result = "\n".join(output)
        page = WEB_HTML.replace("提交后这里会显示结果。", html_escape(result))
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

    missing = [
        name
        for name in ("panel_url", "username", "password", "name_prefix", "inbound_start_port")
        if not getattr(args, name)
    ]
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
