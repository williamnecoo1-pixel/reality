#!/usr/bin/env python3
"""
Check Shadowsocks links that use WebSocket + TLS on port 443.
Requires:
  - Python 3.10+
  - requests
  - Xray binary at ./xray/xray

Supported link style:
  ss://BASE64(method:password)@host:443?plugin=v2ray-plugin%3Btls%3Bhost%3Dexample.com%3Bpath%3D%2Fws#name

Only v2ray-plugin links with TLS and WebSocket mode are accepted.
"""
import base64
import concurrent.futures
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from statistics import median
from urllib.parse import parse_qs, unquote, urlsplit

import requests

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
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/fast/configs.txt",
    "https://raw.githubusercontent.com/LeilaoMi/AutoMergePublicNodes-Optimized/main/output/global.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/patt/batches/batch_002.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/Countries/United_States.txt",
    "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/other/countries/US/alive_US.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub7.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/subs/sub15.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub8.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/005.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vless.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/Countries/Canada.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/country/uk.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/detailed/vless/80.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/HEAD/configs/trojan.txt",
    "https://raw.githubusercontent.com/TheCrowCreature/v2rayExtractor/refs/heads/main/vless.html",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/detailed/vless/8880.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/top100.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs_base64.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_2083.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/patt/protocols/trojan.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/non-tls.txt",
    "https://raw.githubusercontent.com/penhandev/AutoAiVPN/HEAD/allConfigs.txt",
    "https://raw.githubusercontent.com/pie-with-jam/PulseProxy/main/githubmirror/30.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top_ipv6.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/lite/subscriptions/xray/normal/alive-stable",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/main/githubmirror/bypass/bypass-9.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_016.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_2087.txt",
    "https://raw.githubusercontent.com/ninjastrikers/Nexus-nodes/main/configs/light.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/trojan.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/003.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_2096.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/026.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/10ium-telegram-configs-collector-tcp",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs_base64.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/cloudflare.txt",
    "https://raw.githubusercontent.com/mmkeshavarzz/v2ray-configs/HEAD/sub.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_008.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/AllConfigsSub.txt",
    "https://raw.githubusercontent.com/lorenzazy7kenyon/free-vpn-subscriptions/main/output/by-country/v2ray-base64-US.txt",
    "https://raw.githubusercontent.com/asgharkapk/Sub-Config-Extractor/refs/heads/main/output_configs/mixed/10ium/V2Hub3/merged_base64.yaml",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/countries/NL.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/014.txt",
]

XRAY = "./xray/xray"
TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://www.apple.com/library/test/success.html",
]
FETCH_TIMEOUT = 20
TEST_TIMEOUT = 12
MAX_WORKERS = 20
BASE_PORT = 20000
MAX_LATENCY_MS = 10000

SESSION = requests.Session()
SESSION.trust_env = False


def b64decode_text(value):
    value = unquote(value).strip()
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value.encode()).decode("utf-8")


def parse_ss_link(line):
    """Return normalized SS config only if plugin proves WS + TLS + port 443."""
    if not line.lower().startswith("ss://"):
        return None
    try:
        raw = line[5:].split("#", 1)[0]
        parsed = urlsplit("ss://" + raw)
        query = parse_qs(parsed.query, keep_blank_values=True)
        plugin_value = query.get("plugin", [""])[0]
        plugin_value = unquote(plugin_value).strip()
        if not plugin_value:
            return None

        # SIP002 plugin string: v2ray-plugin;tls;host=...;path=/...
        parts = plugin_value.split(";")
        plugin_name = parts[0].strip().lower()
        opts = {}
        flags = set()
        for item in parts[1:]:
            item = item.strip()
            if not item:
                continue
            if "=" in item:
                k, v = item.split("=", 1)
                opts[k.strip().lower()] = v.strip()
            else:
                flags.add(item.lower())

        if plugin_name not in ("v2ray-plugin", "v2ray-plugin.exe"):
            return None
        # v2ray-plugin defaults to websocket mode; reject explicit non-WS mode.
        mode = opts.get("mode", "websocket").lower()
        if mode not in ("websocket", "ws"):
            return None
        if "tls" not in flags and opts.get("tls", "").lower() not in ("1", "true", "yes"):
            return None

        # SIP002 userinfo can be base64(method:password) or plain method:password.
        if not parsed.hostname or parsed.port != 443 or not parsed.username:
            return None
        userinfo = parsed.username
        if ":" not in userinfo:
