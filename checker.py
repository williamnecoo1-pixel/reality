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

# Cloudflare IP used for BOTH testing AND output
CLOUDFLARE_IP = "104.18.37.127"

TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.apple.com/library/test/success.html",
    "http://www.gstatic.com/generate_204",
]

TIMEOUT = 8
MAX_WORKERS = 40
BASE_PORT = 20000
TEST_ROUNDS = 1
MIN_SUCCESS = 1
MAX_LATENCY_MS = 10000

_SESSION = requests.Session()
_SESSION.trust_env = False


# ============================================================
# Cipher blocklist (Xray v25+ removed / v26 rejects)
# ============================================================
BLOCKED_CIPHERS = {
    "none", "plain", "table",
    "rc4", "rc4-md5", "rc4-md5-6",
}


def _is_cipher_supported(method: str) -> bool:
    m = (method or "").strip().lower()
    if not m:
        return False
    if m in BLOCKED_CIPHERS:
        return False
    if m.startswith("rc4"):
        return False
    return True


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
