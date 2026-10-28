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
    "https://github.com/0xRadikal/Free-v2ray-Configs/raw/refs/heads/main/all/configs.txt",
    
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
