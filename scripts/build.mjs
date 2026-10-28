import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
import base64
from statistics import median
from urllib.parse import parse_qs, unquote, urlparse
from collections import Counter

import requests


SOURCE_URLS = [
    "https://github.com/Mohamedhnini-a/Neverstops/raw/refs/heads/main/sub.txt",
    "https://github.com/Mohamedhnini-a/testeur/raw/refs/heads/main/working_configs.txt",
]
XRAY = "./xray/xray"

TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.apple.com/library/test/success.html",
    "http://www.gstatic.com/generate_204",
]

TIMEOUT = 10
MAX_WORKERS = 40
BASE_PORT = 20000
TEST_ROUNDS = 1
MIN_SUCCESS = 1
MAX_LATENCY_MS = 10000

_SESSION = requests.Session()
_SESSION.trust_env = False


def test_once(proxies):
    last_error = None
    for url in TEST_URLS:
        try:
            start = time.perf_counter()
            response = _SESSION.get(url, proxies=proxies, timeout=TIMEOUT, allow_redirects=False)
            elapsed = (time.perf_counter() - start) * 1000

            if response.status_code in (200, 204):
                return round(elapsed), None

            last_error = f"http_{response.status_code}"
            if 500 <= response.status_code < 600:
                continue
            else:
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


def download_configs():
    configs = []
    for source_url in SOURCE_URLS:
        try:
            print(f"Downloading: {source_url}")
            response = requests.get(source_url, timeout=20)
            response.raise_for_status()
            source_configs = [line.strip() for line in response.text.splitlines() if line.strip()]
            print(f"  → {len(source_configs)} lines")
            configs.extend(source_configs)
        except requests.RequestException as error:
            print(f"  → FAILED: {error}")
    configs = list(dict.fromkeys(configs))
    return configs


def parse_ss(line):
    """تحليل روابط Shadowsocks SIP002"""
    try:
        if not line.startswith("ss://"):
            return None

        line_clean = line.split("#")[0]
        body = line_clean[5:]

        # SIP002: userinfo@host:port?plugin=...
        if "@" not in body:
            return None

        userinfo, rest = body.split("@", 1)
        
        # فك تشفير userinfo (method:password)
        try:
            # بعض الروابط كتكون base64
            userinfo_dec = base64.b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode('utf-8')
            if ":" not in userinfo_dec:
                raise ValueError
        except Exception:
            userinfo_dec = unquote(userinfo)
            
        if ":" not in userinfo_dec:
            return None
        method, password = userinfo_dec.split(":", 1)

        host_port, *params = rest.split("?", 1)
        if ":" not in host_port:
            return None
        
        server, port_str = host_port.rsplit(":", 1)
        port = int(port_str)
        
        if port != 443:
            return None
            
        if not params:
            return None
        
        query = parse_qs(params[0])
        plugin_list = query.get("plugin", [])
        if not plugin_list:
            return None
        
        plugin = plugin_list[0]
        
        # الفلترة: خاصنا v2ray-plugin أو xray-plugin و tls
        if not any(x in plugin for x in ["v2ray-plugin", "xray-plugin"]):
            return None
        if "tls" not in plugin.lower():
            return None
            
        # استخراج host و path من الـ plugin
        sni = server
        path = "/"
        for opt in plugin.split(";"):
            if opt.startswith("host="):
                sni = opt.split("=", 1)[1]
            elif opt.startswith("path="):
                path = opt.split("=", 1)[1]

        return {
            "protocol": "ss",
            "server": server,
            "port": 443,
            "method": method,
            "password": password,
            "host": sni,
            "sni": sni,
            "path": path,
            "original": line,
        }
    except Exception:
        return None


def parse_config(line):
    if line.startswith("ss://"):
        return parse_ss(line)
    return None # هنا حيدنا VLESS/VMess/Trojan حيت بغينا SS فقط


def make_xray_config(config, local_port):
    stream_settings = {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
            "serverName": config["sni"],
        },
        "wsSettings": {
            "path": config["path"],
            "headers": {"Host": config["host"]},
        },
    }

    if config["protocol"] == "ss":
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {
                        "address": config["server"],
                        "port": 443,
                        "method": config["method"],
                        "password": config["password"],
                    }
                ]
            },
            "streamSettings": stream_settings,
        }
    else:
        return None

    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "http",
                "settings": {},
            }
        ],
        "outbounds": [outbound],
    }


def validate_xray_config(config_file):
    try:
        result = subprocess.run(
            [XRAY, "run", "-test", "-c", config_file],
            capture_output=True,
            text=True,
            timeout=10,
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
        "line": config["original"],
        "protocol": config.get("protocol", "?"),
        "server": config.get("server", "?"),
    }

    try:
        xray_config = make_xray_config(config, local_port)
        if not xray_config:
            return {**base_result, "ok": False, "latency": None, "latencies": [], "reason": "make_config_failed"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(xray_config, f, ensure_ascii=False)
            config_file = f.name

        is_valid, err = validate_xray_config(config_file)
        if not is_valid:
            return {**base_result, "ok": False, "latency": None, "latencies": [], "reason": f"invalid_config: {err[:120]}"}

        log_file = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name
        log_handle = open(log_file, "w")
        try:
            process = subprocess.Popen([XRAY, "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=log_handle)
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
            return {**base_result, "ok": False, "latency": None, "latencies": [], "reason": f"{reason}({detail})"}

        proxies = {"http": f"http://127.0.0.1:{local_port}", "https": f"http://127.0.0.1:{local_port}"}

        for round_number in range(TEST_ROUNDS):
            latency, err = test_once(proxies)
            if latency is not None:
                latencies.append(latency)
            else:
                last_err = err
            if round_number < TEST_ROUNDS - 1:
                time.sleep(0.15)

        success_count = len(latencies)
        if success_count < MIN_SUCCESS:
            reason = last_err or "request_failed"
            return {**base_result, "ok": False, "latency": None, "latencies": latencies, "reason": reason}

        final_latency = int(median(latencies))
        return {**base_result, "ok": True, "latency": final_latency, "latencies": latencies, "reason": "ok"}

    except Exception as error:
        err_type = type(error).__name__
        return {**base_result, "ok": False, "latency": None, "latencies": latencies, "reason": err_type}

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
                try: os.remove(path)
                except Exception: pass


def main():
    print("\n==============================")
    print(" SHADOWSOCKS (SS) + WS + TLS CHECKER")
    print("==============================\n")

    if not os.path.isfile(XRAY):
        print(f"ERROR: Xray binary not found at '{XRAY}'")
        return

    print("Downloading configs...")
    lines = download_configs()
    print(f"Downloaded: {len(lines)} lines")

    configs = []
    for line in lines:
        config = parse_config(line)
        if config:
            configs.append(config)

    print(f"\nTestable SS+WS+TLS configs : {len(configs)}")

    if not configs:
        print("\nNo SS WS TLS 443 configs found.")
        open("working.txt", "w", encoding="utf-8").close()
        return

    tasks = list(enumerate(configs, start=1))
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        iterator = iter(tasks)
        pending = set()

        for _ in range(MAX_WORKERS):
            try: pending.add(executor.submit(test_config, *next(iterator)))
            except StopIteration: break

        while pending:
            done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                try: results.append(future.result())
                except Exception as e: print(f"[FAILED] Worker error: {str(e)[:100]}")
                try: pending.add(executor.submit(test_config, *next(iterator)))
                except StopIteration: pass

    working_results = [r for r in results if r["ok"]]
    working_results.sort(key=lambda x: (x["latency"], x["index"]))
    fast_results = [r for r in working_results if r["latency"] <= MAX_LATENCY_MS]

    with open("working.txt", "w", encoding="utf-8") as f:
        for r in fast_results:
            f.write(r["line"] + "\n")

    print("\n==============================")
    print(" CHECK FINISHED")
    print("==============================")
    print(f"Working (fast)    : {len(fast_results)}")

    print("\nFastest configs:")
    for pos, r in enumerate(fast_results[:10], start=1):
        print(f"{pos:02d}. {r['latency']} ms | {r.get('protocol','?')} | {r.get('server','?')}")

    print("\nOutput: working.txt")

if __name__ == "__main__":
    main()
