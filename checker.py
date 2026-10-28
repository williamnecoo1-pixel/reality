#!/usr/bin/env python3
"""Shadowsocks WS+TLS:443 checker using Xray; writes tested links to working.txt."""

import base64
import concurrent.futures
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from collections import Counter
from statistics import median
from urllib.parse import parse_qs, unquote, urlsplit

import requests

# Add/remove source URLs here. Accept ANY plugin name, as long as its options explicitly indicate WS + TLS on port 443.
SOURCE_URLS = [
    "https://github.com/Mohamedhnini-a/Neverstops/raw/refs/heads/main/sub.txt",
    
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/10ium/_V2Hub3_shadowsocks.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/vpnclashfa-backup/SubConfigShuffler/MahsaNetConfigTopic.txt.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/10ium/base64-encoder/ndsphonemy/_default.yaml",
    "https://raw.githubusercontent.com/geek-spot/Free-Config/main/vmess",
    "https://raw.githubusercontent.com/6b3478/telegram-configs-collector2/main/subscribe/protocols/reality",
    "https://raw.githubusercontent.com/6b3478/telegram-configs-collector2/main/channels/protocols/vmess",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/muma16fx_netlify_app.yaml",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/ipv6.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/ipv6.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/FobiaLabs/vless-subscription/HEAD/top20_subscription.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/10ium/base64-encoder/shabane/_ss.yaml",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/VG.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/ResistalProxy_server.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/NiREvil_SSTime.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/10ium/base64-encoder/ndsphonemy/_my.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/ResistalProxy_server.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/FreedomGuard_Finder_configs.yaml",
    "https://raw.githubusercontent.com/tahmaseb73/configs-collector-v2ray/refs/heads/main/data/sub/protocols/hysteria2.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/ndsphonemy_my.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/roosterkid/_V2RAY_RAW.yaml",
    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/b64vmess.txt",
    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vmess.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/hamedp-71_openproxylist.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/maimengmeng/000.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/hamedp-71_Sub_Checker_Creator_final.yaml",
    "https://raw.githubusercontent.com/Dev1324/Free-V2ray-Configs-Hiddify/HEAD/Configs",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/10ium/base64-encoder/miladtahanian_config.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/vpnclashfa-backup/MirrorMan/v2nodes.b64.yaml",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/AZ.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/FreedomGuard/_Finder_configs.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/shatakvpn.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/vpnclashfa-backup/MirrorMan/v2nodes.b64.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/lagzian_trinity.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/10ium/base64-encoder/rb360full_Reza-Collection.yaml",
    "https://raw.githubusercontent.com/tahmaseb73/configs-collector-v2ray/refs/heads/main/data/sub/mix_protocol/mix_shadowsocks_1.txt",
    "https://raw.githubusercontent.com/tahmaseb73/configs-collector-v2ray/refs/heads/main/data/sub/mix_protocol/mix_shadowsocks_4.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/IS.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/v2nodes.yaml",
    "https://raw.githubusercontent.com/6b3478/telegram-configs-collector2/main/countries/ir/mixed",
    "https://raw.githubusercontent.com/tahmaseb73/configs-collector-v2ray/refs/heads/main/data/sub/mix_protocol/mix_shadowsocks_5.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/roosterkid_V2RAY_BASE64.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/itsyebekhe_mix.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/10ium_V2RayAggregator-Eternity.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/rayan_proxy.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/10ium/base64-encoder/rb360full_Reza-Collection.yaml",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/HR.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/v2nodes.yaml",
    "https://raw.githubusercontent.com/tahmaseb73/configs-collector-v2ray/refs/heads/main/data/sub/protocols/vless.txt",
    "https://raw.githubusercontent.com/longlon/v2ray-config/HEAD/Sub24.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/10ium/_ss_iran.yaml",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/MO.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/ebrasha_lite.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/roosterkid.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/roosterkid-V2RAY_BASE64.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/ndsphonemy_lt-sub.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/MatinGhanbari/v2ray-configs/subscriptions/v2ray/super-sub.txt.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/Danialsamadi_v2go_custom.yaml",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/EternityAir.txt",
    "https://raw.githubusercontent.com/geek-spot/Free-Config/HEAD/trojan",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/hamedp-71_hp.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/Rayan/-Config_H-I.yaml",
    "https://raw.githubusercontent.com/tahmaseb73/configs-collector-v2ray/refs/heads/main/data/sub/mix_protocol/mix_trojan_4.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/NiREvil_SSTime.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/ndsphonemy/_my.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/10ium_V2Hub3_shadowsocks.yaml",
    "https://raw.githubusercontent.com/ArtemAfonasyev/hentai-goida-subscription/HEAD/subscription-for-ru.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub4.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/FreedomGuard_Finder_configs.yaml",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/1.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/3.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/4.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/5.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/6.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/7.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/8.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/9.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/10.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/11.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/12.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/13.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/15.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/16.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/17.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/18.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/19.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/20.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/21.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/22.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/23.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/24.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/26.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/34.txt",
    "https://translate.yandex.ru/translate?url=https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/Export/Base64/PROXIES_ONLY/WHITE-SNI-RU-all-base64.txt&lang=de-de",
    "https://translate.yandex.ru/translate?url=https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/Export/v2rayN_PC/WHITE-SNI-RU-all-v2rayN.txt&lang=de-de",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/2.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/14.2.txt",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/25.2.txt",
    "https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/Export/Base64/PROXIES_ONLY/WHITE-SNI-RU-all-base64.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/vpnclashfa-backup/SubConfigShuffler/roosterkid_v2ray.txt.yaml",
    "https://raw.githubusercontent.com/ArtemAfonasyev/hentai-goida-subscription/HEAD/subscription-ru.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/subs/sub4.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/shatakvpn.yaml",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Luxembourg.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-HiN-VPN-hysteria2",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/10ium-HiN-VPN-hysteria2",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/10ium_V2RayAggregator-Eternity.yaml",
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/exclave-wg.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub3.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/ss/lagzian_mix.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/v2ray/Mosifree_Vmess.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/maimengmeng/_500.yaml",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/subs/sub3.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/10ium/base64-encoder/shabane/_ss.yaml",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/10ium/_hin-vpn-mix.yaml",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/archives/202607/2026-07-20_19-42-30/mixed",

]

XRAY = "./xray/xray"
REWRITE_IP = "104.18.37.127"
TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://www.apple.com/library/test/success.html",
]
TIMEOUT = 10
DOWNLOAD_TIMEOUT = 20
MAX_WORKERS = 30
BASE_PORT = 20000
MAX_LATENCY_MS = 10000


def b64decode_text(value):
    value = unquote(value.strip())
    value += "=" * ((4 - len(value) % 4) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(value.encode("ascii")).decode("utf-8")
        except Exception:
            pass
    return None


def parse_ss_uri(line):
    """Parse SIP002 SS URI. Do not filter by plugin name; require only WS + TLS metadata and port 443."""
    line = line.strip()
    if not line.lower().startswith("ss://"):
        return None

    try:
        parsed = urlsplit(line)
        if not parsed.netloc:
            return None

        # Standard SIP002: ss://base64(method:password)@host:port/?plugin=...
        # Legacy form: ss://base64(method:password@host:port)#tag (plugin data is unavailable).
        if "@" in parsed.netloc:
            userinfo, authority = parsed.netloc.rsplit("@", 1)
            decoded_userinfo = b64decode_text(userinfo)
            if decoded_userinfo and ":" in decoded_userinfo:
                method, password = decoded_userinfo.split(":", 1)
            elif ":" in unquote(userinfo):
                method, password = unquote(userinfo).split(":", 1)
            else:
                return None

            # Parse host:port from the authority without assuming a DNS hostname.
            auth_parsed = urlsplit("//" + authority)
            server = auth_parsed.hostname
            port = auth_parsed.port
            if not server or port is None:
                return None
        else:
            # Legacy whole-payload links cannot express the required plugin query reliably.
            return None

        query = parse_qs(parsed.query, keep_blank_values=True)
        plugin_values = query.get("plugin", [])
        if not plugin_values:
            return None

        # IMPORTANT: the plugin name is intentionally ignored. Read only the
        # transport options, so v2ray-plugin is NOT a required name.
        plugin_spec = plugin_values[0]
        parts = [part.strip() for part in plugin_spec.split(";") if part.strip()]
        options = {}
        flags = set()
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                options[key.strip().lower()] = value.strip()
            else:
                flags.add(part.strip().lower())

        mode = options.get("mode", "websocket").strip().lower()
        if mode not in ("websocket", "ws"):
            return None
        tls_enabled = (
            "tls" in flags
            or options.get("tls", "").strip().lower() in ("1", "true", "yes")
        )
        if not tls_enabled or port != 443:
            return None

        host = options.get("host") or server
        sni = options.get("host") or server
        path = options.get("path") or "/"
        if not path.startswith("/"):
            path = "/" + path
        if not method or not password:
            return None

        # Keep the original URL's userinfo/query/tag but rewrite only the server authority.
        # This keeps the plugin's Host/SNI/path options intact in the subscription output.
        prefix = line[: line.find("ss://") + 5]
        after_scheme = line[5:]
        if "@" not in after_scheme:
            return None
        before_at, after_at = after_scheme.rsplit("@", 1)
        # Strip path/query/fragment from authority, retaining the rest verbatim.
        match = re.match(r"([^/?#]+)(.*)$", after_at)
        if not match:
            return None
        rewritten_line = prefix + before_at + "@" + REWRITE_IP + ":443" + match.group(2)

        return {
            "protocol": "shadowsocks",
            "server": REWRITE_IP,
            "original_server": server,
            "port": 443,
            "method": method,
            "password": password,
            "host": host,
            "sni": sni,
            "path": path,
            "original": line,
            "output_line": rewritten_line,
        }
    except (ValueError, UnicodeError, IndexError):
        return None
    except Exception:
        return None


def download_configs():
    all_lines = []
    session = requests.Session()
    session.trust_env = False
    for source_url in SOURCE_URLS:
        try:
            print(f"Downloading: {source_url}")
            response = session.get(source_url, timeout=DOWNLOAD_TIMEOUT)
            response.raise_for_status()
            lines = [line.strip() for line in response.text.splitlines() if line.strip()]
            print(f"  -> {len(lines)} non-empty lines")
            all_lines.extend(lines)
        except requests.RequestException as exc:
            print(f"  -> FAILED: {exc}")
    return list(dict.fromkeys(all_lines))


def make_xray_config(config, local_port):
    # Xray carries the Shadowsocks stream through WS/TLS. Host/SNI are kept from plugin options.
    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": config["server"],
                "port": 443,
                "method": config["method"],
                "password": config["password"],
            }]
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "tlsSettings": {"serverName": config["sni"]},
            "wsSettings": {
                "path": config["path"],
                "headers": {"Host": config["host"]},
            },
        },
    }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "http",
            "settings": {},
        }],
        "outbounds": [outbound],
    }


def validate_xray_config(config_file):
    try:
        result = subprocess.run(
            [XRAY, "run", "-test", "-c", config_file],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return True, None
        message = (result.stderr or result.stdout or "invalid Xray config").strip()
        return False, " | ".join(message.splitlines()[-2:])[:250]
    except subprocess.TimeoutExpired:
        return False, "xray_test_timeout"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:150]}"


def test_http_through_proxy(local_port):
    proxy_url = f"http://127.0.0.1:{local_port}"
    last_error = "request_failed"
    # A separate Session per worker avoids sharing requests.Session across threads.
    with requests.Session() as session:
        session.trust_env = False
        for url in TEST_URLS:
            try:
                start = time.perf_counter()
                response = session.get(
                    url,
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=TIMEOUT,
                    allow_redirects=False,
                )
                elapsed = round((time.perf_counter() - start) * 1000)
                status = response.status_code
                response.close()
                if status in (200, 204):
                    return elapsed, None
                last_error = f"http_{status}"
                if 500 <= status < 600:
                    continue
                return None, last_error
            except requests.exceptions.Timeout:
                last_error = "timeout"
            except requests.exceptions.ProxyError:
                return None, "proxy_error"
            except requests.exceptions.SSLError:
                last_error = "ssl_error"
            except requests.exceptions.ConnectionError:
                last_error = "connection_error"
            except Exception as exc:
                last_error = type(exc).__name__
    return None, last_error


def test_config(index, config):
    local_port = BASE_PORT + index
    config_file = None
    process = None
    log_file = None
    base = {
        "index": index,
        "line": config["output_line"],
        "server": config["server"],
        "ok": False,
        "latency": None,
        "reason": "unknown",
    }
    try:
        xray_config = make_xray_config(config, local_port)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump(xray_config, handle, ensure_ascii=False)
            config_file = handle.name

        valid, error = validate_xray_config(config_file)
        if not valid:
            base["reason"] = f"invalid_config: {error}"
            print(f"[FAILED] {config['original_server']} | {base['reason']}")
            return base

        log_handle = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8")
        log_file = log_handle.name
        log_handle.close()
        with open(log_file, "w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [XRAY, "run", "-c", config_file],
                stdout=subprocess.DEVNULL,
                stderr=log,
            )

        started = False
        for _ in range(30):
            if process.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.25):
                    started = True
                    break
            except OSError:
                time.sleep(0.1)
        if not started:
            base["reason"] = "xray_died" if process.poll() is not None else "xray_no_port"
            print(f"[FAILED] {config['original_server']} | {base['reason']}")
            return base

        latency, error = test_http_through_proxy(local_port)
        if latency is None:
            base["reason"] = error or "request_failed"
            print(f"[FAILED:{base['reason']}] {config['original_server']}")
            return base
        if latency > MAX_LATENCY_MS:
            base["reason"] = f"too_slow_{latency}ms"
            print(f"[SLOW] {latency} ms | {config['original_server']}")
            return base

        base.update(ok=True, latency=latency, reason="ok")
        print(f"[ONLINE] {latency} ms | {config['original_server']} -> {REWRITE_IP}")
        return base
    except Exception as exc:
        base["reason"] = type(exc).__name__
        print(f"[FAILED:{base['reason']}] {config.get('original_server', '?')} | {str(exc)[:100]}")
        return base
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=1)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=1)
                except Exception:
                    pass
        for path in (config_file, log_file):
            if path:
                try:
                    os.remove(path)
                except OSError:
                    pass


def main():
    print("\n====================================")
    print(" SHADOWSOCKS WS + TLS :443 CHECKER")
    print("====================================\n")
    if not os.path.isfile(XRAY):
        print(f"ERROR: Xray binary not found: {XRAY}")
        open("working.txt", "w", encoding="utf-8").close()
        raise SystemExit(1)

    try:
        version = subprocess.run([XRAY, "version"], capture_output=True, text=True, timeout=5)
        print((version.stdout or version.stderr).strip()[:300])
    except Exception as exc:
        print(f"WARNING: could not read Xray version: {exc}")

    lines = download_configs()
    configs = []
    dropped = 0
    for line in lines:
        parsed = parse_ss_uri(line)
        if parsed:
            configs.append(parsed)
        else:
            dropped += 1

    # Deduplicate by the rewritten output link.
    unique = {}
    for config in configs:
        unique.setdefault(config["output_line"], config)
    configs = list(unique.values())

    print(f"Downloaded lines : {len(lines)}")
    print(f"SS WS/TLS/443    : {len(configs)}")
    print(f"Dropped/filtered : {dropped}")
    print(f"Rewrite IP       : {REWRITE_IP}")
    print(f"Workers          : {MAX_WORKERS}")

    results = []
    if configs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = [pool.submit(test_config, i, config) for i, config in enumerate(configs, start=1)]
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    print(f"[WORKER ERROR] {type(exc).__name__}: {str(exc)[:100]}")

    working = [result for result in results if result.get("ok")]
    working.sort(key=lambda item: (item["latency"], item["index"]))
    # Preserve order by latency and remove duplicate output lines.
    output_lines = list(dict.fromkeys(item["line"] for item in working))
    with open("working.txt", "w", encoding="utf-8") as output:
        for line in output_lines:
            output.write(line + "\n")

    reasons = Counter(item.get("reason", "unknown") for item in results if not item.get("ok"))
    print("\n============== RESULT ==============")
    print(f"Tested   : {len(results)}")
    print(f"Working  : {len(output_lines)}")
    print(f"Failed   : {len(results) - len(working)}")
    for reason, count in reasons.most_common(10):
        print(f"{reason:28s} {count}")
    print("Output: working.txt")


if __name__ == "__main__":
    main()
