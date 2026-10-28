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
