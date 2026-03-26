import re
import requests
from .keys import VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY

# ------------------------------------------
# Type detection
# ------------------------------------------
def detect_type(value):
    value = value.strip()

    # IP
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ip"

    # URL
    if value.startswith("http://") or value.startswith("https://"):
        return "url"

    # DOMAIN
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value) and "://" not in value:
        return "domain"

    # JA3 / JA3S (32 char MD5)
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "ja3"

    # FILE HASH (md5/sha1/sha256 etc.)
    if re.match(r"^[a-fA-F0-9]{32,64}$", value):
        return "hash"

    return "unknown"

# ------------------------------------------
# VIRUSTOTAL API Wrappers
# ------------------------------------------

def vt_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    return _vt_get(url)

def vt_url(url_value):
    url = "https://www.virustotal.com/api/v3/urls"
    return _vt_post_url(url_value)

def vt_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    return _vt_get(url)

def vt_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    return _vt_get(url)

def vt_ja3(ja3_hash):
    url = f"https://www.virustotal.com/api/v3/files/{ja3_hash}"
    return _vt_get(url)

def _vt_get(url):
    headers = {"x-apikey": VT_API_KEY}
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r.json()
    return {"error": r.text}

def _vt_post_url(url_value):
    """
    VT requires URL submission before scanning.
    """
    headers = {"x-apikey": VT_API_KEY}
    payload = {"url": url_value}
    r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=payload)

    if r.status_code != 200:
        return {"error": r.text}

    scan_id = r.json()["data"]["id"]
    get_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

    r2 = requests.get(get_url, headers=headers)
    return r2.json()

# ------------------------------------------
# Classification Logic
# ------------------------------------------
def classify_value(value):
    v_type = detect_type(value)

    vt_result = None
    final_score = 0

    # -------------------------
    # IP
    # -------------------------
    if v_type == "ip":
        vt = vt_ip(value)
        vt_m = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = vt_m.get("malicious", 0)
        suspicious = vt_m.get("suspicious", 0)
        final_score = (malicious * 70) + (suspicious * 30)
        return _format(value, final_score)

    # -------------------------
    # URL
    # -------------------------
    elif v_type == "url":
        vt = vt_url(value)
        stats = vt.get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        final_score = (malicious * 70) + (suspicious * 30)
        return _format(value, final_score)

    # -------------------------
    # DOMAIN
    # -------------------------
    elif v_type == "domain":
        vt = vt_domain(value)
        stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        final_score = (malicious * 70) + (suspicious * 30)
        return _format(value, final_score)

    # -------------------------
    # FILE HASH
    # -------------------------
    elif v_type == "hash":
        vt = vt_hash(value)
        stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        final_score = (stats.get("malicious", 0) * 70) + (stats.get("suspicious", 0) * 30)
        return _format(value, final_score)

    # -------------------------
    # JA3 / JA3S
    # -------------------------
    elif v_type == "ja3":
        vt = vt_ja3(value)
        stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        final_score = (stats.get("malicious", 0) * 70) + (stats.get("suspicious", 0) * 30)
        return _format(value, final_score)

    # -------------------------
    # UNKNOWN
    # -------------------------
    return {
        "value": value,
        "classification": "UNKNOWN",
        "final_score": 0,
        "confidence": "LOW"
    }

# ------------------------------------------
# SCORE → LABEL
# ------------------------------------------
def _format(value, score):
    if score == 0:
        return {"value": value, "classification": "CLEAN", "confidence": "LOW", "final_score": score}
    if 1 <= score <= 40:
        return {"value": value, "classification": "SUSPICIOUS", "confidence": "MEDIUM", "final_score": score}
    if score > 40:
        return {"value": value, "classification": "MALICIOUS", "confidence": "HIGH", "final_score": score}
