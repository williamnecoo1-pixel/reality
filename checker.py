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

# Add/remove source URLs here. Only SS links using v2ray-plugin WS + TLS on port 443 are accepted.
SOURCE_URLS = [
    "https://raw.githubusercontent.com/MustafaBaqer/VestraNet-Nodes/refs/heads/main/subscriptions/mix-normal.txt",
  "https://github.com/barry-far/V2ray-Config/raw/refs/heads/main/All_Configs_Sub.txt",
  "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
  "https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/top100.txt",
  "https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/all/configs.txt",
  "https://github.com/YawStar/Proxy-Hunter/raw/refs/heads/main/configs/proxy_configs.txt",
  "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_013.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/011.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/trojan.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/008.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-trojan",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/tls.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/009.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/medium.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_015.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/002.txt",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/vless",
    "https://raw.githubusercontent.com/TheCrowCreature/v2rayExtractor/refs/heads/main/trojan.html",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/vless.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-78.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-35.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/shadowsocks.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/028.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/MH.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_011.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_005.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_011.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_008.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_013.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_004.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_007.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_007.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_002.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_009.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_009.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_012.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_006.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_006.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_003.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_003.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_014.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-13.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_014.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/countries/US.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/mini.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/027.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/USA.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_005.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/countries/US.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/015.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_015.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/non-tls.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/019.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/ws.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/trojan.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/datacenters/cloudflare.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/033.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/037.txt",
    "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/main/public/trojan.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/007.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/datacenters/cloudflare.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/main/output/kind/trojan.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/ss.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/035.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_002.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/IM.txt",
    "https://raw.githubusercontent.com/thealiiakbarii-ai/VCC/main/configs/all.txt",
    "https://raw.githubusercontent.com/thealiiakbarii-ai/VCC/main/configs/vless.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/reality.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/10ium-telegram-configs-collector-trojan",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-tls",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/001.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-ws",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/10ium-telegram-configs-collector-ws",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/018.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/10ium-telegram-configs-collector-tls",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_010.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-vless",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/025.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/10ium-telegram-configs-collector-vless",
    "https://raw.githubusercontent.com/freenodess/freenodess/refs/heads/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/protocols/vless.txt",
    "https://raw.githubusercontent.com/Meret2019/vless-subscription/HEAD/subscription_base64.txt",
    "https://raw.githubusercontent.com/Freedom-Guard-Builder/Freedom-Finder/main/out/channels/PSG.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/USA.txt",
    "https://clashxw.github.io/uploads/2026/10/1-20261025.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/iran.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/038.txt",
    "https://raw.githubusercontent.com/lorenzazy7kenyon/free-vpn-subscriptions/main/output/by-country/v2ray-base64-CA.txt",
    "https://raw.githubusercontent.com/EEvanescence/4Diana/main/By-protocol/cloudflare.txt",
    "https://raw.githubusercontent.com/komoterdon/free-sub/HEAD/sub.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/030.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/029.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/036.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/006.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/Countries/Canada.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/tcp-pass/batch_004.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/032.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/013.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/transports/tls_base64.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/transports/ws_tls.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/protocols/trojan.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/protocols/trojan_base64.txt",
    "https://vless.svinakraft.workers.dev/vless.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/034.txt",
    "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/main/public/vless.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/HEAD/configs/trojan_sub.txt",
    "https://raw.githubusercontent.com/lorenzazy7kenyon/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_443.txt",
    "https://raw.githubusercontent.com/Mokafela/Config-Finder/master/split/sub-ALL.txt",
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/all.txt",
    "https://raw.githubusercontent.com/indelingDanil/MyAppVPN-subs/output/vless.txt",
    "https://raw.githack.com/indelingDanil/MyAppVPN-subs/output/vless.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/regions/North_America.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/detailed/trojan/443.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_010.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/trojan_sub.txt",
    "https://raw.githubusercontent.com/EEvanescence/4Diana/main/By-protocol/vless.txt",
    "https://raw.githubusercontent.com/DaBao-Lee/V2RayN-NodeShare/main/base64",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-25.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_001.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/HEAD/configs/vless.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/012.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/031.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/config.txt",
    "https://vless.svinakraft.workers.dev/fastest.txt",
    "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/main/public/fastest.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/vless.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_012.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/output/vless.txt",
    "https://raw.githubusercontent.com/balochscript/free-vpn-configs/gh-pages/subscription-tcping.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt",
    "https://leidahub.top/v2ray.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/fast/configs_base64.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/022.txt",
    "https://vless.svinakraft.workers.dev/trojan.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/datacenters/fastly.txt",
    "https://clashxw.github.io/uploads/2026/10/2-20261025.txt",
    "https://raw.githubusercontent.com/thealiiakbarii-ai/VCC/main/configs/lite.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/trojan.txt",
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/vless.txt",
    "https://raw.githubusercontent.com/mohammadaz2/v2rayConfigsForYou/main/sub/trojan.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/023.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/datacenters/fastly.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/LU.txt",
    "https://raw.githubusercontent.com/penhandev/AutoAiVPN/HEAD/russia.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/ws.txt",
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
    """Parse SIP002 SS URI and require v2ray-plugin WebSocket + TLS + port 443."""
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

        plugin_spec = unquote(plugin_values[0])
        parts = [part for part in plugin_spec.split(";") if part]
        plugin_name = parts[0].strip().lower() if parts else ""
        options = {}
        flags = set()
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                options[key.strip().lower()] = value.strip()
            else:
                flags.add(part.strip().lower())

        if plugin_name not in ("v2ray-plugin", "v2ray_plugin"):
            return None
        if options.get("mode", "websocket").lower() not in ("websocket", "ws"):
            return None
        tls_enabled = "tls" in flags or options.get("tls", "").lower() in ("1", "true", "yes")
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
