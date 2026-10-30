#!/usr/bin/env python3
"""把各种格式的订阅内容统一解析成 Clash/mihomo 代理字典列表。

支持：Clash YAML、base64(v2ray 链接)、明文 v2ray 链接、sing-box JSON。
"""
import base64
import json
import re
import sys
import urllib.parse as up

import yaml

LINK_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
                "hysteria2://", "hy2://", "hysteria://", "tuic://",
                "anytls://", "socks5://", "http://")


def b64d(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s, validate=False)


def maybe_b64_text(text):
    """若整段内容像是 base64，则解码；否则返回 None。"""
    t = re.sub(r'\s+', '', text)
    if len(t) < 40 or not re.fullmatch(r'[A-Za-z0-9+/\-_=]+', t):
        return None
    try:
        raw = b64d(t)
        out = raw.decode('utf-8')
    except Exception:
        return None
    if '://' in out:
        return out
    return None


def split_host_port(hp):
    hp = hp.strip()
    if hp.startswith('['):
        h, _, p = hp[1:].partition(']:')
        return h, int(p)
    h, _, p = hp.rpartition(':')
    return h, int(p)


def qs(q):
    return {k: v[0] for k, v in up.parse_qs(q, keep_blank_values=True).items()}


def safe_int(v, d=0):
    try:
        return int(str(v).strip())
    except Exception:
        return d


def truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb",
    "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5",
    "chacha20-ietf", "xchacha20", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "none", "dummy", "aes-128-ccm", "lea-128-gcm", "lea-192-gcm",
    "lea-256-gcm", "rabbit128-poly1305", "aegis-128l", "aegis-256",
}


# ───────────────────────── 链接解析 ─────────────────────────
def p_vmess(u, name_hint):
    body = u[len("vmess://"):].split('#')[0]
    try:
        j = json.loads(b64d(body))
    except Exception:
        return None
    server = str(j.get('add', '')).strip()
    port = safe_int(j.get('port'))
    uuid = str(j.get('id', '')).strip()
    if not server or not port or not uuid:
        return None
    net = str(j.get('net', 'tcp')).strip().lower() or 'tcp'
    host = str(j.get('host', '')).strip()
    path = str(j.get('path', '')).strip()
    tls = str(j.get('tls', '')).strip().lower() in ('tls', 'reality', 'xtls')
    sni = str(j.get('sni', '')).strip()
    p = {
        "name": str(j.get('ps') or name_hint or f"{server}:{port}").strip(),
        "type": "vmess", "server": server, "port": port, "uuid": uuid,
        "alterId": safe_int(j.get('aid', 0)), "cipher": "auto", "udp": True,
    }
    scy = str(j.get('scy', '')).strip()
    if scy and scy.lower() != 'auto':
        p["cipher"] = scy
    if tls:
        p["tls"] = True
        p["servername"] = sni or host or server
        fp = str(j.get('fp', '')).strip()
        if fp:
            p["client-fingerprint"] = fp
        if truthy(j.get('insecure', '0')):
            p["skip-cert-verify"] = True
    if net in ('ws', 'httpupgrade'):
        p["network"] = net
        opts = {"path": path or "/"}
        if host:
            opts["headers"] = {"Host": host}
        p["ws-opts" if net == 'ws' else "ws-opts"] = opts
    elif net == 'grpc':
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": path or str(j.get('serviceName', ''))}
    elif net in ('h2', 'http'):
        p["network"] = "h2"
        o = {"path": path or "/"}
        if host:
            o["host"] = [h.strip() for h in host.split(',') if h.strip()]
        p["h2-opts"] = o
    alpn = str(j.get('alpn', '')).strip()
    if alpn:
        p["alpn"] = [a.strip() for a in alpn.split(',') if a.strip()]
    return p


def p_vless(u, name_hint):
    try:
        s = up.urlsplit(u)
    except Exception:
        return None
    if not s.hostname or not s.port:
        return None
    q = qs(s.query)
    uid = up.unquote(s.username or '')
    if not uid:
        return None
    net = (q.get('type') or 'tcp').lower()
    sec = (q.get('security') or '').lower()
    p = {
        "name": up.unquote(s.fragment) or name_hint or f"{s.hostname}:{s.port}",
        "type": "vless", "server": s.hostname, "port": int(s.port),
        "uuid": uid, "udp": True,
    }
    if sec in ('tls', 'reality', 'xtls'):
        p["tls"] = True
        sni = q.get('sni') or q.get('peer') or q.get('host') or ''
        p["servername"] = sni or s.hostname
        if q.get('fp'):
            p["client-fingerprint"] = q['fp']
        if sec == 'reality':
            p["reality-opts"] = {"public-key": q.get('pbk', ''),
                                 "short-id": q.get('sid', '')}
            if not q.get('pbk'):
                return None
        if truthy(q.get('allowInsecure', q.get('insecure', ''))):
            p["skip-cert-verify"] = True
        if q.get('alpn'):
            p["alpn"] = [a for a in q['alpn'].split(',') if a]
    if q.get('flow'):
        p["flow"] = q['flow']
    if net == 'ws':
        p["network"] = "ws"
        o = {"path": q.get('path', '/') or '/'}
        if q.get('host'):
            o["headers"] = {"Host": q['host']}
        p["ws-opts"] = o
    elif net == 'grpc':
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": q.get('serviceName', '')}
    elif net in ('h2', 'http'):
        p["network"] = "h2"
        o = {"path": q.get('path', '/') or '/'}
        if q.get('host'):
            o["host"] = [h for h in q['host'].split(',') if h]
        p["h2-opts"] = o
    elif net == 'httpupgrade':
        p["network"] = "httpupgrade"
        p["ws-opts"] = {"path": q.get('path', '/') or '/'}
        if q.get('host'):
            p["ws-opts"]["headers"] = {"Host": q['host']}
    return p


def p_trojan(u, name_hint):
    try:
        s = up.urlsplit(u)
    except Exception:
        return None
    if not s.hostname or not s.port:
        return None
    q = qs(s.query)
    p = {
        "name": up.unquote(s.fragment) or name_hint or f"{s.hostname}:{s.port}",
        "type": "trojan", "server": s.hostname, "port": int(s.port),
        "password": up.unquote(s.username or ''), "udp": True,
        "sni": q.get('sni') or q.get('peer') or '',
    }
    if not p["sni"]:
        p["sni"] = q.get('host') or s.hostname
    if truthy(q.get('allowInsecure', q.get('insecure', ''))):
        p["skip-cert-verify"] = True
    if q.get('alpn'):
        p["alpn"] = [a for a in q['alpn'].split(',') if a]
    net = (q.get('type') or 'tcp').lower()
    if net == 'ws':
        p["network"] = "ws"
        o = {"path": q.get('path', '/') or '/'}
        if q.get('host'):
            o["headers"] = {"Host": q['host']}
        p["ws-opts"] = o
    elif net == 'grpc':
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": q.get('serviceName', '')}
    return p


def p_ss(u, name_hint):
    raw = u[len("ss://"):]
    frag = ''
    if '#' in raw:
        raw, frag = raw.split('#', 1)
    if '?' in raw:
        raw, query = raw.split('?', 1)
    else:
        query = ''
    if '@' in raw:
        head, _, hostpart = raw.rpartition('@')
        try:
            dec = b64d(head).decode()
            method, _, password = dec.partition(':')
        except Exception:
            method, _, password = head.partition(':')
        try:
            host, port = split_host_port(up.unquote(hostpart))
        except Exception:
            return None
    else:
        try:
            dec = b64d(raw).decode()
        except Exception:
            return None
        if '@' not in dec:
            return None
        creds, _, hostpart = dec.rpartition('@')
        method, _, password = creds.partition(':')
        try:
            host, port = split_host_port(hostpart)
        except Exception:
            return None
    method = method.strip().lower()
    if method in ('chacha20-poly1305', 'chacha20'):
        method = 'chacha20-poly1305'
    if method not in SS_CIPHERS:
        return None
    p = {
        "name": up.unquote(frag) or name_hint or f"{host}:{port}",
        "type": "ss", "server": host, "port": port,
        "cipher": method, "password": password, "udp": True,
    }
    q = qs(query)
    plugin = q.get('plugin', '')
    if plugin:
        parts = plugin.split(';')
        pname = parts[0].strip()
        popts = {}
        for kv in parts[1:]:
            k, _, v = kv.partition('=')
            popts[k.strip()] = v.strip()
        if pname in ('obfs-local', 'simple-obfs', 'obfs'):
            p["plugin"] = "obfs"
            p["plugin-opts"] = {"mode": popts.get('obfs', 'http'),
                                "host": popts.get('obfs-host', '')}
        elif pname == 'v2ray-plugin':
            p["plugin"] = "v2ray-plugin"
            p["plugin-opts"] = {"mode": "websocket",
                                "host": popts.get('host', ''),
                                "path": popts.get('path', '/'),
                                "tls": 'tls' in popts}
        else:
            return None
    return p


def p_ssr(u, name_hint):
    try:
        dec = b64d(u[len("ssr://"):]).decode()
    except Exception:
        return None
    main, _, query = dec.partition('/?')
    parts = main.split(':')
    if len(parts) < 6:
        return None
    host = parts[0]
    port = safe_int(parts[1])
    protocol, method, obfs = parts[2], parts[3], parts[4]
    pw_b64 = ':'.join(parts[5:])
    q = qs(query)
    try:
        password = b64d(pw_b64).decode()
    except Exception:
        return None
    if not host or not port:
        return None
    name = name_hint or f"{host}:{port}"
    if q.get('remarks'):
        try:
            name = b64d(q['remarks']).decode()
        except Exception:
            pass
    p = {"name": name, "type": "ssr", "server": host, "port": port,
         "cipher": method, "password": password, "protocol": protocol,
         "obfs": obfs, "udp": True}
    if q.get('protoparam'):
        try:
            p["protocol-param"] = b64d(q['protoparam']).decode()
        except Exception:
            pass
    if q.get('obfsparam'):
        try:
            p["obfs-param"] = b64d(q['obfsparam']).decode()
        except Exception:
            pass
    return p


def p_hy2(u, name_hint):
    try:
        s = up.urlsplit(u)
    except Exception:
        return None
    if not s.hostname or not s.port:
        return None
    q = qs(s.query)
    p = {"name": up.unquote(s.fragment) or name_hint or f"{s.hostname}:{s.port}",
         "type": "hysteria2", "server": s.hostname, "port": int(s.port),
         "password": up.unquote(s.username or '')}
    if q.get('sni') or q.get('peer'):
        p["sni"] = q.get('sni') or q.get('peer')
    if truthy(q.get('insecure', q.get('allowInsecure', ''))):
        p["skip-cert-verify"] = True
    if q.get('obfs') and q['obfs'] != 'none':
        p["obfs"] = q['obfs']
        p["obfs-password"] = q.get('obfs-password', '')
    if q.get('alpn'):
        p["alpn"] = [a for a in q['alpn'].split(',') if a]
    return p


def p_tuic(u, name_hint):
    try:
        s = up.urlsplit(u)
    except Exception:
        return None
    if not s.hostname or not s.port:
        return None
    q = qs(s.query)
    p = {"name": up.unquote(s.fragment) or name_hint or f"{s.hostname}:{s.port}",
         "type": "tuic", "server": s.hostname, "port": int(s.port),
         "uuid": up.unquote(s.username or ''),
         "password": up.unquote(s.password or '')}
    if q.get('sni'):
        p["sni"] = q['sni']
    if q.get('alpn'):
        p["alpn"] = [a for a in q['alpn'].split(',') if a]
    if q.get('congestion_control'):
        p["congestion-controller"] = q['congestion_control']
    if q.get('udp_relay_mode'):
        p["udp-relay-mode"] = q['udp_relay_mode']
    if truthy(q.get('allow_insecure', q.get('insecure', ''))):
        p["skip-cert-verify"] = True
    return p


PARSERS = {
    "vmess://": p_vmess,
    "vless://": p_vless,
    "trojan://": p_trojan,
    "ss://": p_ss,
    "ssr://": p_ssr,
    "hysteria2://": p_hy2,
    "hy2://": p_hy2,
    "tuic://": p_tuic,
}


def parse_link(line):
    for sch, fn in PARSERS.items():
        if line.lower().startswith(sch):
            try:
                return fn(line, '')
            except Exception:
                return None
    return None


# ───────────────────────── sing-box JSON ─────────────────────────
def sb_outbound(o):
    t = o.get('type')
    server = o.get('server')
    port = safe_int(o.get('server_port'))
    if not server or not port:
        return None
    name = o.get('tag') or f"{server}:{port}"
    tls = o.get('tls') or {}
    tr = o.get('transport') or {}
    p = {"name": name, "server": server, "port": port}
    if t == 'vless':
        p.update({"type": "vless", "uuid": o.get('uuid', ''), "udp": True})
        if tls.get('enabled'):
            p["tls"] = True
            p["servername"] = tls.get('server_name') or server
            if tls.get('insecure'):
                p["skip-cert-verify"] = True
            r = tls.get('reality') or {}
            if r.get('enabled') or r.get('public_key'):
                p["reality-opts"] = {"public-key": r.get('public_key', ''),
                                     "short-id": r.get('short_id', '')}
            fp = ((tls.get('utls') or {}).get('fingerprint'))
            if fp:
                p["client-fingerprint"] = fp
            if tls.get('alpn'):
                p["alpn"] = tls['alpn']
        if o.get('flow'):
            p["flow"] = o['flow']
    elif t == 'vmess':
        p.update({"type": "vmess", "uuid": o.get('uuid', ''),
                  "alterId": safe_int(o.get('alter_id', 0)),
                  "cipher": o.get('security') or 'auto', "udp": True})
        if tls.get('enabled'):
            p["tls"] = True
            p["servername"] = tls.get('server_name') or server
            if tls.get('insecure'):
                p["skip-cert-verify"] = True
    elif t == 'trojan':
        p.update({"type": "trojan", "password": o.get('password', ''),
                  "udp": True, "sni": (tls.get('server_name') or server)})
        if tls.get('insecure'):
            p["skip-cert-verify"] = True
    elif t == 'shadowsocks':
        p.update({"type": "ss", "cipher": o.get('method', ''),
                  "password": o.get('password', ''), "udp": True})
    elif t == 'hysteria2':
        p.update({"type": "hysteria2", "password": o.get('password', '')})
        if tls.get('server_name'):
            p["sni"] = tls['server_name']
        if tls.get('insecure'):
            p["skip-cert-verify"] = True
    elif t == 'tuic':
        p.update({"type": "tuic", "uuid": o.get('uuid', ''),
                  "password": o.get('password', '')})
    else:
        return None
    if tr.get('type') == 'ws':
        p["network"] = "ws"
        opts = {"path": tr.get('path', '/') or '/'}
        h = (tr.get('headers') or {}).get('Host')
        if h:
            opts["headers"] = {"Host": h if isinstance(h, str) else h[0]}
        p["ws-opts"] = opts
    elif tr.get('type') == 'grpc':
        p["network"] = "grpc"
        p["grpc-opts"] = {"grpc-service-name": tr.get('service_name', '')}
    return p


# ───────────────────────── 入口 ─────────────────────────
def parse_file(path):
    """返回 (格式名, [proxy dict])"""
    raw = open(path, 'rb').read()
    text = raw.decode('utf-8', 'ignore').lstrip('\ufeff')

    if text.lstrip().startswith('{'):
        try:
            j = json.loads(text)
            obs = j.get('outbounds') or []
            return "singbox-json", [x for x in (sb_outbound(o) for o in obs) if x]
        except Exception:
            return "json-invalid", []

    # Clash YAML
    try:
        y = yaml.safe_load(text)
        if isinstance(y, dict) and isinstance(y.get('proxies'), list):
            out = []
            for pr in y['proxies']:
                if isinstance(pr, dict) and pr.get('server') and pr.get('port'):
                    pr = dict(pr)
                    pr['name'] = str(pr.get('name') or
                                     f"{pr['server']}:{pr['port']}")
                    pr['port'] = safe_int(pr['port'])
                    out.append(pr)
            return "clash-yaml", out
    except Exception:
        pass

    # base64 包裹的链接
    dec = maybe_b64_text(text)
    body = dec if dec else text
    fmt = "base64-links" if dec else "plain-links"
    out = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '://' not in line:
            continue
        pr = parse_link(line)
        if pr:
            out.append(pr)
    return fmt, out


if __name__ == "__main__":
    for p in sys.argv[1:]:
        f, nodes = parse_file(p)
        print(p, f, len(nodes))
