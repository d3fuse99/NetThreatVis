import json
import urllib.request
import socket
import ipaddress
import sqlite3
import time
from config import CACHE_DB_FILE, CACHE_TTL_DAYS, IP_API_URL, IP_API_BATCH_URL, DNSBL_LIST

socket.setdefaulttimeout(1.5)

def get_db_connection():
    return sqlite3.connect(CACHE_DB_FILE, timeout=10.0)

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS geolocations (
                ip TEXT PRIMARY KEY,
                lat REAL,
                lon REAL,
                city TEXT,
                country TEXT,
                country_code TEXT,
                isp TEXT,
                org TEXT,
                as_num TEXT,
                hostname TEXT,
                timestamp INTEGER
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass

def country_code_to_flag(code):
    if not code or len(code) != 2:
        return "🌐"
    code = code.upper()
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

def get_cached_geolocation(ip):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT lat, lon, city, country, country_code, isp, org, as_num, hostname, timestamp FROM geolocations WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        conn.close()
        if row:
            lat, lon, city, country, country_code, isp, org, as_num, hostname, ts = row
            if int(time.time()) - ts < (CACHE_TTL_DAYS * 86400):
                return {
                    "status": "success",
                    "query": ip,
                    "lat": lat,
                    "lon": lon,
                    "city": city,
                    "country": country,
                    "countryCode": country_code,
                    "flag": country_code_to_flag(country_code),
                    "isp": isp,
                    "org": org,
                    "as": as_num,
                    "hostname": hostname
                }
    except Exception:
        pass
    return None

def save_geolocation_to_cache(ip, data, hostname):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO geolocations (ip, lat, lon, city, country, country_code, isp, org, as_num, hostname, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            data.get("lat", 0.0),
            data.get("lon", 0.0),
            data.get("city", "Unknown"),
            data.get("country", "Unknown"),
            data.get("countryCode", ""),
            data.get("isp", "Unknown"),
            data.get("org", "Unknown"),
            data.get("as", "Unknown"),
            hostname,
            int(time.time())
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def get_geolocation(ip=""):
    init_db()
    if ip:
        cached = get_cached_geolocation(ip)
        if cached:
            return cached
    
    try:
        url = IP_API_URL + ip
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 NetworkThreatVisualizer"})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                resolved_ip = data.get("query", ip)
                hostname = get_hostname(resolved_ip)
                save_geolocation_to_cache(resolved_ip, data, hostname)
                data["hostname"] = hostname
                data["flag"] = country_code_to_flag(data.get("countryCode", ""))
                return data
    except Exception:
        pass
    return None

def get_geolocations_batch(ip_list):
    init_db()
    results = {}
    uncached = []

    for ip in ip_list:
        cached = get_cached_geolocation(ip)
        if cached:
            results[ip] = cached
        else:
            uncached.append(ip)

    if uncached:
        try:
            payload = json.dumps(uncached).encode("utf-8")
            req = urllib.request.Request(
                IP_API_BATCH_URL,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 NetworkThreatVisualizer"
                }
            )
            with urllib.request.urlopen(req, timeout=5.0) as response:
                batch_data = json.loads(response.read().decode())
                for item in batch_data:
                    if isinstance(item, dict) and item.get("status") == "success":
                        res_ip = item.get("query")
                        hostname = get_hostname(res_ip)
                        save_geolocation_to_cache(res_ip, item, hostname)
                        item["hostname"] = hostname
                        item["flag"] = country_code_to_flag(item.get("countryCode", ""))
                        results[res_ip] = item
        except Exception:
            for ip in uncached:
                res = get_geolocation(ip)
                if res:
                    results[ip] = res

    return results

def check_dnsbl_single(ip, dnsbl):
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = reversed_ip + "." + dnsbl
        res = socket.gethostbyname(query)
        if res and res != "127.0.0.2":
            return dnsbl
        return None
    except Exception:
        return None

def check_dnsbl(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return []
    except Exception:
        return []

    listed_in = []
    for dnsbl in DNSBL_LIST:
        res = check_dnsbl_single(ip, dnsbl)
        if res:
            listed_in.append(res)
    return listed_in

def evaluate_reputation(ip, isp_name, org_name, process_path=""):
    score = 0
    factors = []
    
    dc_keywords = ["hosting", "cloud", "amazon", "google", "microsoft", "digitalocean", "hetzner", "ovh", "datacenter", "server", "vps", "linode"]
    combined = (str(isp_name) + " " + str(org_name)).lower()
    is_dc = any(kw in combined for kw in dc_keywords)
    
    if is_dc:
        score += 30
        factors.append("Hosting / Datacenter IP")
    else:
        factors.append("Residential IP (Low Risk)")
        
    path_lower = (process_path or "").lower()
    if any(p in path_lower for p in ["appdata", "temp", "tmp", "downloads"]):
        score += 35
        factors.append("Process running from temporary/untrusted directory")

    dnsbl_matches = check_dnsbl(ip)
    if dnsbl_matches:
        score += 40
        factors.append("Listed in DNSBL: " + ", ".join(dnsbl_matches))
        
    return min(score, 100), factors