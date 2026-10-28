import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
import base64
from statistics import median
from urllib.parse import unquote
from collections import Counter

import requests


# ============================================================
# CONFIG
# ============================================================
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
    "https://raw.githubusercontent.com/EEvanescence/4Diana/main/AllConfigsSub.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/detailed/vless/2087.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_8880.txt",
    "https://alireza786786.github.io/Free-V2ray-Configs/servers/trojan.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/base64/subs/sub29.txt",
    "https://raw.githubusercontent.com/kasesm/Free-Config/refs/heads/main/trojan_raw.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/024.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/transports/tls.txt",
    "https://raw.githubusercontent.com/chenzhihan1751-cyber/node-sub-zixf/main/sub/base64.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/countries/DE.txt",
    "https://raw.githubusercontent.com/miraali1372/mirsub/main/subscription.txt",
    "https://raw.githubusercontent.com/B3B3097/REMAININGCONNECTIONS/main/data/subscriptions_found.json",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/patt/all.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/protocols/vless.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless.txt",
    "https://raw.githubusercontent.com/Meret2019/vless-subscription/HEAD/subscription.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-reality",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/vless.txt",
    "https://raw.githubusercontent.com/lorenzazy7kenyon/free-vpn-subscriptions/main/output/by-country/v2ray-base64-NL.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_2095.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/AllConfigsSub.txt",
    "https://raw.githubusercontent.com/chenzhihan1751-cyber/node-sub-zixf/HEAD/sub/base64.txt",
    "https://raw.githubusercontent.com/PlanAslii/vira-v2ray-configs/main/protocols/vless.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/020.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/countries/IR.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/Delta-Kronecker_trojan",
    "https://raw.githubusercontent.com/SoliSpirit/SolVPN/main/Protocols/trojan.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/0xRadikal-Free-v2ray-verified.txt",
    "https://raw.githubusercontent.com/Seyedhub/Subscription/HEAD/sub.txt",
    "https://raw.githubusercontent.com/pashadolf/Eternal-Sub/main/Github-Gemini.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/all-verified/v2ray-base64-0003.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/mix",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/main/category/Canada.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/0xRadikal-Free-v2ray-fast.txt",
    "https://raw.githubusercontent.com/LeilaoMi/AutoMergePublicNodes-Optimized/main/output/verified.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/0xRadikal-Free-v2ray-verified.txt",
    "https://raw.githubusercontent.com/pie-with-jam/PulseProxy/main/githubmirror/13.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/countries/us.txt",
    "https://raw.githubusercontent.com/gbcwror/v2ray-tester/HEAD/configs/trojan/trojan-1.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/main/conf-week.txt",
    "https://gh-proxy.com/https://raw.githubusercontent.com/chenzhihan1751-cyber/node-sub-zixf/main/sub/base64.txt",
    "https://raw.githubusercontent.com/pie-with-jam/PulseProxy/main/githubmirror/18.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/ipv4.txt",
    "https://raw.githubusercontent.com/YawStar/Proxy-Hunter/refs/heads/main/configs/proxy_configs_deduplicated.txt",
    "https://raw.githubusercontent.com/cbusifabcap/daily_free_vpn/main/sub/sub.yml",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-V2Hub3-trojan",
    "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/main/public/Top500.txt",
    "https://raw.githack.com/sakazxc1400-creator/free-vpn-sub/data/output/sub.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/021.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/split/xhttp.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/0xRadikal-Free-v2ray-top100.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/0xRadikal-Free-v2ray-top100.txt",
    "https://raw.githubusercontent.com/chenzhihan1751-cyber/node-sub-zixf/HEAD/sub/v2ray.txt",
    "https://raw.githubusercontent.com/aviamastersgh/vpn-free-russia/main/verified_configs.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/lite/subscriptions/xray/normal/alive-fast",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/config.txt",
    "https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/HEAD/verified/configs_base64.txt",
    "https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/main/verified/configs_base64.txt",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list_raw.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/normal/10ium-telegram-configs-collector-non-tls",
    "https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/light-base64.txt",
    "https://raw.githubusercontent.com/PlanAslii/vira-v2ray-configs/main/all.txt",
    "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_plain_full.txt",
    "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt",
    "https://raw.githubusercontent.com/noahclanman/free-xray-gcp/main/output/transports/ws_tls_base64.txt",
    "https://raw.githubusercontent.com/drmikecrypto/PulseConfigs/HEAD/protocols/vless_base64.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/trojan.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/self/tested/trojan.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/trojan.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/010.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/004.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified_tls.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/countries/ca.txt",
    "https://radarhub.top/v2ray.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/split/tls.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/MT.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/peasoft-NoMoreWalls-list_raw.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/roosterkid-openproxylist-V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Mokafela/Config-Finder/master/split/sub-CA.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/countries/ca.txt",
    "https://raw.githubusercontent.com/arg9244/V2R-Subs/HEAD/subs/1000/017.txt",
    "https://alireza786786.github.io/Free-V2ray-Configs/servers/vless.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/all-verified/v2ray-base64-0004.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/HEAD/configs/mix.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni-local/vless.txt",
    "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/10ium-V2Hub3-trojan",
]
XRAY = "./xray/xray"

# ← Cloudflare IP used for BOTH testing AND output
CLOUDFLARE_IP = "104.18.37.127"

TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.apple.com/library/test/success.html",
    "http://www.gstatic.com/generate_204",
]

TIMEOUT = 8                # ← lowered from 10 (Cloudflare configs are fast)
MAX_WORKERS = 40
BASE_PORT = 20000
TEST_ROUNDS = 1
MIN_SUCCESS = 1
MAX_LATENCY_MS = 10000

_SESSION = requests.Session()
_SESSION.trust_env = False


# ============================================================
# Helpers
# ============================================================

def _b64decode(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s).decode("utf-8")


def _parse_query(query: str) -> dict:
    params = {}
    for pair in query.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
        else:
            k, v = pair, ""
        params[unquote(k)] = unquote(v)
    return params


def _parse_userinfo(userinfo: str):
    unquoted = unquote(userinfo)
    if ":" in unquoted:
        return unquoted.split(":", 1)
    try:
        decoded = _b64decode(unquoted)
        if ":" in decoded:
            return decoded.split(":", 1)
    except Exception:
        pass
    return None


# ============================================================
# Network test
# ============================================================

def test_once(proxies):
    last_error = None
    for url in TEST_URLS:
        try:
            start = time.perf_counter()
            response = _SESSION.get(
                url, proxies=proxies, timeout=TIMEOUT, allow_redirects=False,
            )
            elapsed = (time.perf_counter() - start) * 1000

            if response.status_code in (200, 204):
                return round(elapsed), None

            last_error = f"http_{response.status_code}"
            if 500 <= response.status_code < 600:
                continue
            return None, last_error

        except requests.exceptions.Timeout:
            last_error = "timeout"
        except requests.exceptions.ProxyError:
            return None, "proxy_error"
        except requests.exceptions.SSLError:
            last_error = "ssl_error"
        except requests.exceptions.ConnectionError:
            last_error = "conn_error"
        except Exception as e:
            last_error = type(e).__name__

    return None, last_error


# ============================================================
# Download
# ============================================================

def download_configs():
    configs = []
    for source_url in SOURCE_URLS:
        try:
            print(f"Downloading: {source_url}")
            response = requests.get(source_url, timeout=20)
            response.raise_for_status()
            source_configs = [l.strip() for l in response.text.splitlines() if l.strip()]
            print(f"  → {len(source_configs)} lines")
            configs.extend(source_configs)
        except requests.RequestException as error:
            print(f"  → FAILED: {error}")
    return list(dict.fromkeys(configs))


# ============================================================
# Parse (STRICT: only ss+v2ray-plugin+ws+tls+443)
# ============================================================

def parse_config(line: str):
    if not line.startswith("ss://"):
        return None
    try:
        raw = line[5:].strip()

        if "#" in raw:
            raw, _tag = raw.split("#", 1)

        # Plugin query is required for this strict mode
        if "?" not in raw:
            return None
        raw, query = raw.split("?", 1)
        params = _parse_query(query)
        plugin_str = params.get("plugin", "")
        if not plugin_str:
            return None

        # Reject legacy format (no plugin anyway)
        if "@" not in raw:
            return None
        userinfo, server_part = raw.rsplit("@", 1)
        creds = _parse_userinfo(userinfo)
        if creds is None:
            return None
        method, password = creds

        # host:port
        server_part = server_part.split("/", 1)[0]
        if server_part.startswith("["):
            host, rest = server_part[1:].split("]", 1)
            port_str = rest.lstrip(":")
        else:
            host, port_str = server_part.rsplit(":", 1)
        port = int(port_str)

        if not method or not password or not host:
            return None

        # ─── STRICT FILTER ───
        if port != 443:
            return None

        parts = plugin_str.split(";")
        plugin_name = parts[0]
        opts = {}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                opts[k] = v
            elif part:
                opts[part] = True

        if plugin_name != "v2ray-plugin":
            return None
        if opts.get("mode", "websocket") != "websocket":
            return None
        if opts.get("tls") not in (True, "true"):
            return None

        ws_host = opts.get("host") or host
        ws_path = opts.get("path") or "/"

        return {
            "protocol": "ss",
            "server": host,
            "port": port,
            "method": method,
            "password": password,
            "plugin": {
                "name": "v2ray-plugin",
                "tls": True,
                "host": ws_host,
                "path": ws_path,
            },
            "original": line,
        }
    except Exception:
        return None


# ============================================================
# Xray config builder (uses CLOUDFLARE_IP, SNI/Host = original)
# ============================================================

def make_xray_config(config, local_port):
    return {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "http",
            "settings": {},
        }],
        "outbounds": [{
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": CLOUDFLARE_IP,       # ← Cloudflare IP
                    "port": config["port"],         # 443
                    "method": config["method"],
                    "password": config["password"],
                    "level": 0,
                }]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "serverName": config["plugin"]["host"],   # SNI = original host
                },
                "wsSettings": {
                    "path": config["plugin"]["path"],
                    "headers": {"Host": config["plugin"]["host"]},
                },
            },
        }],
    }


# ============================================================
# Output URI rebuild (swap server → CLOUDFLARE_IP)
# ============================================================

def _rebuild_output_uri(config):
    """Rebuild ss:// URI preserving everything but server host."""
    orig = config["original"]
    raw = orig[5:]

    tag_suffix = ""
    if "#" in raw:
        raw, tag_part = raw.split("#", 1)
        tag_suffix = "#" + tag_part

    query_suffix = ""
    if "?" in raw:
        raw, query_part = raw.split("?", 1)
        query_suffix = "?" + query_part

    if "@" not in raw:
        return orig  # shouldn't happen

    userinfo, _old_server = raw.rsplit("@", 1)
    return f"ss://{userinfo}@{CLOUDFLARE_IP}:{config['port']}{query_suffix}{tag_suffix}"


# ============================================================
# Validation / run
# ============================================================

def validate_xray_config(config_file):
    try:
        result = subprocess.run(
            [XRAY, "run", "-test", "-c", config_file],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            msg = (result.stderr or result.stdout or "").strip()
            lines = [ln for ln in msg.splitlines() if ln.strip()]
            return False, " | ".join(lines[-2:])[:250]
        return True, None
    except subprocess.TimeoutExpired:
        return False, "xray_test_timeout"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:150]}"


def _read_log(log_file, max_lines=3, max_chars=250):
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as lf:
            lines = [ln.strip() for ln in lf.read().splitlines() if ln.strip()]
            return " | ".join(lines[:max_lines])[:max_chars]
    except Exception:
        return ""


def test_config(index, config):
    local_port = BASE_PORT + index
    config_file = None
    log_file = None
    process = None
    latencies = []
    last_err = None

    base_result = {
        "index": index,
        "line": _rebuild_output_uri(config),   # ← output uses Cloudflare IP
        "protocol": config.get("protocol", "?"),
        "server": config.get("server", "?"),
    }

    try:
        xray_config = make_xray_config(config, local_port)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(xray_config, f, ensure_ascii=False)
            config_file = f.name

        is_valid, err = validate_xray_config(config_file)
        if not is_valid:
            print(f"[FAILED:invalid_config] {config.get('server','?')} | {err}")
            return {**base_result, "ok": False, "latency": None,
                    "latencies": [], "reason": f"invalid_config: {err[:120]}"}

        log_file = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name
        log_handle = open(log_file, "w")
        try:
            process = subprocess.Popen(
                [XRAY, "run", "-c", config_file],
                stdout=subprocess.DEVNULL, stderr=log_handle,
            )
        finally:
            log_handle.close()

        started = False
        for _ in range(20):
            if process.poll() is not None:
                break
            try:
                sock = socket.create_connection(("127.0.0.1", local_port), timeout=0.5)
                sock.close()
                started = True
                break
            except OSError:
                time.sleep(0.1)

        if not started:
            exit_code = process.poll()
            time.sleep(0.2)
            xray_err = _read_log(log_file)
            detail = f"exit={exit_code}|err={xray_err or 'empty'}"
            reason = "xray_died" if exit_code is not None else "xray_no_port"
            print(f"[FAILED:{reason}] {config.get('server','?')} | {detail}")
            return {**base_result, "ok": False, "latency": None,
                    "latencies": [], "reason": f"{reason}({detail})"}

        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}",
        }

        for round_number in range(TEST_ROUNDS):
            latency, err = test_once(proxies)
            if latency is not None:
                latencies.append(latency)
            else:
                last_err = err
            if round_number < TEST_ROUNDS - 1:
                time.sleep(0.15)

        if len(latencies) < MIN_SUCCESS:
            reason = last_err or "request_failed"
            print(f"[FAILED:{reason}] {config.get('server','?')} | {len(latencies)}/{TEST_ROUNDS}")
            return {**base_result, "ok": False, "latency": None,
                    "latencies": latencies, "reason": reason}

        final_latency = int(median(latencies))
        print(f"[ONLINE] {final_latency} ms | {config['server']} → {CLOUDFLARE_IP}:443 "
              f"| host={config['plugin']['host']}")
        return {**base_result, "ok": True, "latency": final_latency,
                "latencies": latencies, "reason": "ok"}

    except Exception as error:
        err_type = type(error).__name__
        print(f"[FAILED:{err_type}] {config.get('server','?')} | {str(error)[:100]}")
        return {**base_result, "ok": False, "latency": None,
                "latencies": latencies, "reason": err_type}

    finally:
        if process:
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
                except Exception:
                    pass


# ============================================================
# Main
# ============================================================

def main():
    print("\n==============================")
    print(" SS CHECKER — STRICT MODE")
    print(" ss + v2ray-plugin + WS + TLS + 443")
    print(f" Cloudflare IP : {CLOUDFLARE_IP}")
    print("==============================\n")

    if not os.path.isfile(XRAY):
        print(f"ERROR: Xray binary not found at '{XRAY}'")
        return

    try:
        ver = subprocess.run([XRAY, "version"], capture_output=True, text=True, timeout=5)
        print("=== Xray version ===")
        print(ver.stdout.strip()[:400] or ver.stderr.strip()[:400])
        print("====================\n")
    except Exception as e:
        print(f"WARNING: couldn't get xray version: {e}\n")

    print("Downloading configs...")
    lines = download_configs()
    print(f"Downloaded: {len(lines)} lines")

    parse_stats = Counter()
    configs = []
    for line in lines:
        config = parse_config(line)
        if config:
            configs.append(config)
            parse_stats["accepted (ss+v2ray-plugin+ws+tls+443)"] += 1
        else:
            parse_stats["dropped (not matching filter)"] += 1

    print(f"\n--- Parse stage ---")
    for key, count in parse_stats.items():
        print(f"  {key:40s}: {count}")

    # Dedupe by identity (server+method+password+plugin host+path)
    def _key(c):
        return (c["server"], c["port"], c["method"], c["password"],
                c["plugin"]["host"], c["plugin"]["path"])
    seen = set()
    unique = []
    for c in configs:
        k = _key(c)
        if k not in seen:
            seen.add(k)
            unique.append(c)
    dupes_removed = len(configs) - len(unique)
    configs = unique
    if dupes_removed:
        print(f"  duplicates removed                       : {dupes_removed}")

    print(f"\nTestable configs : {len(configs)}")
    print(f"TEST_URLS        : {TEST_URLS}")
    print(f"Rounds per config: {TEST_ROUNDS}")
    print(f"Max latency (ms) : {MAX_LATENCY_MS}")

    if not configs:
        print("\nNo SS WS+TLS 443 configs found.")
        open("working.txt", "w", encoding="utf-8").close()
        return

    tasks = list(enumerate(configs, start=1))
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        iterator = iter(tasks)
        pending = set()

        for _ in range(MAX_WORKERS):
            try:
                pending.add(executor.submit(test_config, *next(iterator)))
            except StopIteration:
                break

        while pending:
            done, pending = concurrent.futures.wait(
                pending, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                try:
                    results.append(future.result())
                except Exception as e:
                    print(f"[FAILED] Worker error: {str(e)[:100]}")
                try:
                    pending.add(executor.submit(test_config, *next(iterator)))
                except StopIteration:
                    pass

    working_results = [r for r in results if r["ok"]]
    failed_results = [r for r in results if not r["ok"]]
    working_results.sort(key=lambda x: (x["latency"], x["index"]))

    fast_results = [r for r in working_results if r["latency"] <= MAX_LATENCY_MS]
    slow_count = len(working_results) - len(fast_results)

    with open("working.txt", "w", encoding="utf-8") as f:
        for r in fast_results:
            f.write(r["line"] + "\n")

    working_count = len(fast_results)
    failed_count = len(failed_results)

    print("\n==============================")
    print(" CHECK FINISHED")
    print("==============================")
    print(f"Total downloaded  : {len(lines)}")
    print(f"Tested            : {len(configs)}")
    print(f"Working (fast)    : {working_count}")
    print(f"Filtered slow     : {slow_count}  (>{MAX_LATENCY_MS}ms)")
    print(f"Failed            : {failed_count}")

    if failed_count:
        print("\n--- Failure reasons ---")
        overall = Counter(r.get("reason", "unknown") for r in failed_results)
        for reason, count in overall.most_common(10):
            pct = 100 * count / failed_count
            print(f"  {count:5d} ({pct:5.1f}%)  {reason}")

    print("\nFastest configs:")
    for pos, r in enumerate(fast_results[:10], start=1):
        print(f"{pos:02d}. {r['latency']} ms | {r.get('server','?')}")

    print("\nOutput: working.txt")


if __name__ == "__main__":
    main()
