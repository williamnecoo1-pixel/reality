import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
import base64
import threading
import random
from urllib.parse import parse_qs, unquote, urlparse

import requests
import urllib3

# إخفاء التحذيرات الخاصة بعدم التحقق من الشهادات
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIGURATION (تم تسريع الإعدادات لتجنب Timeout)
# ============================================================

SOURCE_URLS = [
    "https://github.com/Mohamedhnini-a/Neverstops/raw/refs/heads/main/sub.txt",
    "https://github.com/Mohamedhnini-a/Neverstops-2/raw/refs/heads/main/sub.txt",
]

XRAY = "./xray/xray"

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]

TIMEOUT = 10           # ✅ نقصناها من 15 لـ 10
MAX_WORKERS = 10       # ✅ زدناها باش نسرعو العملية
BASE_PORT = 10808
MAX_LATENCY_MS = 8000
RETRIES = 1            # ✅ نقصناها باش ما نضيعوش الوقت فالمحاولات الفاشلة
STARTUP_TIMEOUT = 3    # ✅ نقصناها حيت Xray كيقلع بسرعة
RETRY_DELAY = 0.5      # ✅ نقصناها

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

_tls = threading.local()


# ============================================================
# SESSION
# ============================================================

def get_session():
    if not hasattr(_tls, "session"):
        session = requests.Session()
        session.trust_env = False
        session.verify = False  # ✅ تعطيل التحقق من الشهادات
        _tls.session = session
    return _tls.session


# ============================================================
# HTTP TEST
# ============================================================

def test_once(proxies):
    session = get_session()
    errors = []

    for url in TEST_URLS:
        try:
            start = time.perf_counter()
            response = session.get(
                url,
                proxies=proxies,
                timeout=(TIMEOUT, TIMEOUT),
                allow_redirects=False,
                headers={
                    "User-Agent": DEFAULT_UA,
                    "Cache-Control": "no-cache",
                },
            )
            elapsed = round((time.perf_counter() - start) * 1000)

            if response.status_code in (200, 204):
                return elapsed, None

            errors.append(f"{url}: http_{response.status_code}")

        except requests.exceptions.SSLError as e:
            errors.append(f"{url}: tls_error: {str(e)[:150]}")
        except requests.exceptions.ProxyError as e:
            errors.append(f"{url}: proxy_error: {str(e)[:150]}")
        except requests.exceptions.ConnectionError as e:
            errors.append(f"{url}: connection_error: {str(e)[:150]}")
        except requests.exceptions.Timeout as e:
            errors.append(f"{url}: timeout: {str(e)[:100]}")
        except Exception as e:
            errors.append(f"{url}: {type(e).__name__}: {str(e)[:100]}")

    return None, " || ".join(errors)


def test_with_retries(proxies):
    last_error = "unknown"
    for attempt in range(RETRIES + 1):
        latency, error = test_once(proxies)
        if latency is not None and error is None:
            return latency, None
        last_error = error or "unknown"
        if last_error.startswith("proxy_error"):
            break
        if attempt < RETRIES:
            time.sleep(RETRY_DELAY + random.uniform(0, 0.2))
    return None, last_error


# ============================================================
# DOWNLOAD CONFIGS
# ============================================================

def download_configs():
    configs = []
    for source_url in SOURCE_URLS:
        try:
            print(f"Downloading: {source_url}", flush=True)
            response = requests.get(
                source_url,
                timeout=30,
                headers={"User-Agent": "NeverStops-Checker/1.0"},
            )
            response.raise_for_status()
            configs.extend(
                line.strip() for line in response.text.splitlines() if line.strip()
            )
        except Exception as e:
            print(f"[DOWNLOAD FAILED] {type(e).__name__}: {e}", flush=True)
    return list(dict.fromkeys(configs))


# ============================================================
# PARSE CONFIGS
# ============================================================

def parse_config(line):
    try:
        if line.startswith("vmess://"):
            b64 = line[8:].split("#", 1)[0].strip()
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            config = json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))

            sni = str(config.get("sni") or config.get("host") or "").strip()
            host = str(config.get("host") or config.get("sni") or "").strip()

            return {
                "protocol": "vmess",
                "server": config.get("add", "").strip(),
                "port": int(config.get("port", 443)),
                "id": config.get("id"),
                "aid": int(config.get("aid", 0)),
                "scy": config.get("scy", "auto"),
                "net": (config.get("net") or "tcp").lower(),
                "security": (config.get("tls") or "none").lower(),
                "sni": sni,
                "host": host,
                "path": str(config.get("path", "/")).strip(),
                "alpn": str(config.get("alpn", "")).strip(),
                "original": line,
            }

        if line.startswith(("vless://", "trojan://")):
            parsed = urlparse(line)
            params = parse_qs(parsed.query, keep_blank_values=True)

            def get(name):
                return params.get(name, [""])[0].strip()

            protocol = parsed.scheme.lower()
            username = unquote(parsed.username or "")

            host = get("host") or ""
            sni = get("sni") or host or parsed.hostname

            return {
                "protocol": protocol,
                "server": parsed.hostname.strip(),
                "port": parsed.port or 443,
                "uuid": username,
                "password": unquote(parsed.password or username),
                "net": (get("type") or "tcp").lower(),
                "security": (get("security") or "none").lower(),
                "sni": sni,
                "host": host,
                "path": unquote(get("path")) or "/",
                "alpn": get("alpn") or "",
                "fp": get("fp") or "",
                "pbk": get("pbk") or "",
                "sid": get("sid") or "",
                "spx": unquote(get("spx") or "/"),
                "flow": get("flow") or "",
                "original": line,
            }
    except Exception:
        return None
    return None


# ============================================================
# BUILD XRAY CONFIG
# ============================================================

def make_xray_config(config, local_port):
    server = config.get("server")
    port = config.get("port")

    if not server or not port:
        return None

    security = (config.get("security") or config.get("tls") or "none").lower()
    network = (config.get("net") or "tcp").lower()

    sni = str(config.get("sni") or config.get("host") or server).strip()
    host = str(config.get("host") or config.get("sni") or server).strip()

    path = config.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path

    stream = {
        "network": network,
        "security": security,
    }

    if security == "tls":
        tls_settings = {
            "serverName": sni,
            "allowInsecure": True, # ✅ ضروري لتجاوز أخطاء الشهادات
            "fingerprint": config.get("fp") or "chrome",
        }

        # ✅ ALPN: مع ws خاصو يكون http/1.1 بوحدو
        if config.get("alpn"):
            alpn_list = [x.strip() for x in config["alpn"].split(",") if x.strip()]
            if network == "ws":
                tls_settings["alpn"] = ["http/1.1"]
            else:
                tls_settings["alpn"] = alpn_list
        else:
            if network == "ws":
                tls_settings["alpn"] = ["http/1.1"]
            else:
                tls_settings["alpn"] = ["h2", "http/1.1"]

        stream["tlsSettings"] = tls_settings

    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": config.get("fp") or "chrome",
            "publicKey": config.get("pbk") or "",
            "shortId": config.get("sid") or "",
            "spiderX": config.get("spx") or "/",
        }

    # ✅ WebSocket: إضافة Host و User-Agent
    if network == "ws":
        ws = {
            "path": path,
        }
        if host:
            ws["headers"] = {
                "Host": host,
                "User-Agent": DEFAULT_UA,
            }
        stream["wsSettings"] = ws

    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": config.get("path") or ""}

    elif network == "http":
        stream["httpSettings"] = {
            "path": path,
            "host": [host],
        }

    if config["protocol"] == "vless":
        user = {"id": config.get("uuid", ""), "encryption": "none"}
        if config.get("flow"):
            user["flow"] = config["flow"]
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": server, "port": port, "users": [user]}]},
            "streamSettings": stream,
        }
    elif config["protocol"] == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": server, "port": port, "password": config.get("password", "")}]},
            "streamSettings": stream,
        }
    elif config["protocol"] == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [{
                        "id": config.get("id", ""),
                        "alterId": config.get("aid", 0),
                        "security": config.get("scy", "auto"),
                    }],
                }]
            },
            "streamSettings": stream,
        }
    else:
        return None

    return {
        "log": {
            "loglevel": "warning", # تقليل اللوغات باش ما تخنقش النظام
            "error": "/dev/stderr",
            "access": "/dev/stdout",
        },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": local_port,
            "protocol": "http",
            "settings": {},
        }],
        "outbounds": [outbound],
    }


# ============================================================
# TEST CONFIG
# ============================================================

def test_config(index, config):
    local_port = BASE_PORT + (index % 40000)
    config_file = None
    log_file = None
    process = None

    try:
        xray_config = make_xray_config(config, local_port)
        if not xray_config:
            return {"ok": False, "reason": "make_failed", "server": config.get("server", "unknown")}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(xray_config, f)
            config_file = f.name

        log_file = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name

        with open(log_file, "w") as log_handle:
            process = subprocess.Popen(
                [XRAY, "run", "-c", config_file],
                stdout=log_handle,
                stderr=log_handle,
                start_new_session=True,
            )

        started = False
        deadline = time.monotonic() + STARTUP_TIMEOUT

        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.25):
                    started = True
                    break
            except OSError:
                time.sleep(0.1)

        if not started:
            xray_error = ""
            if log_file and os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                        xray_error = f.read()[-1000:]
                except Exception:
                    pass
            return {
                "ok": False,
                "reason": f"xray_start_failed: {xray_error[-200:]}",
                "server": config.get("server", "unknown"),
            }

        # ✅ فرصة إضافية لـ Xray باش يكمل الـ Handshake مع السيرفر البعيد
        time.sleep(0.5)

        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}",
        }

        latency, error = test_with_retries(proxies)

        if latency is not None:
            if latency <= MAX_LATENCY_MS:
                return {
                    "ok": True,
                    "latency": latency,
                    "line": config["original"],
                    "server": config.get("server", "unknown"),
                }
            return {
                "ok": False,
                "reason": "latency_too_high",
                "server": config.get("server", "unknown"),
            }

        xray_error = ""
        if log_file and os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    xray_error = f.read()[-500:]
            except Exception:
                pass

        return {
            "ok": False,
            "reason": f"{error} | XRAY_LOG: {xray_error}",
            "server": config.get("server", "unknown"),
        }

    except Exception as e:
        return {
            "ok": False,
            "reason": type(e).__name__,
            "server": config.get("server", "unknown"),
        }
    finally:
        if process:
            try:
                process.terminate()
                process.wait(timeout=1)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

        for path in (config_file, log_file):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass


# ============================================================
# MAIN
# ============================================================

def main():
    print("Downloading configs...", flush=True)
    lines = download_configs()
    configs = [config for config in (parse_config(line) for line in lines) if config]
    total = len(configs)
    print(f"\nTotal configs to test: {total}\n", flush=True)

    if not configs:
        print("No valid configs found.", flush=True)
        return

    results = []
    completed = 0
    working_count = 0
    failed_count = 0
    tasks = iter(enumerate(configs, start=1))

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        pending = set()

        for _ in range(MAX_WORKERS):
            try:
                pending.add(executor.submit(test_config, *next(tasks)))
            except StopIteration:
                break

        while pending:
            done, pending = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            for future in done:
                completed += 1
                try:
                    result = future.result()
                    if result.get("ok"):
                        working_count += 1
                        results.append(result)
                        print(f"[ONLINE] {result['latency']}ms | {result['server']}", flush=True)
                    else:
                        failed_count += 1
                        print(f"[FAILED] {result.get('server')} | {result.get('reason')}", flush=True)
                except Exception as e:
                    failed_count += 1
                    print(f"[WORKER ERROR] {type(e).__name__}", flush=True)

                if completed % 10 == 0 or completed == total:
                    print(
                        f"--- [Progress] {completed}/{total} | "
                        f"Working: {working_count} | "
                        f"Failed: {failed_count} | "
                        f"Remaining: {total - completed} ---",
                        flush=True,
                    )

                try:
                    pending.add(executor.submit(test_config, *next(tasks)))
                except StopIteration:
                    pass

    results.sort(key=lambda x: x["latency"])

    with open("working.txt", "w", encoding="utf-8") as f:
        for result in results:
            f.write(result["line"] + "\n")

    print(f"\nDone! Saved {len(results)} working configs to working.txt", flush=True)


if __name__ == "__main__":
    main()
