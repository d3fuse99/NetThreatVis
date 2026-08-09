import os
import time
import webbrowser
import json
import threading
import platform
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from config import SERVER_HOST, SERVER_PORT, MAX_WORKERS
from geo import get_geolocation, evaluate_reputation
from network import get_connections
from map_gen import HTML_TEMPLATE

SCAN_STATE = {
    "status": "idle",
    "total": 0,
    "current": 0,
    "current_ip": "",
    "local_geo": {},
    "remote_data": []
}

CURRENT_LANG = "en"

TRANSLATIONS = {
    "en": {
        "title": "Threat Intelligence Command Center",
        "badge": "Active Sockets",
        "btn_5": "Limit 5",
        "btn_10": "Limit 10",
        "btn_15": "Limit 15",
        "btn_all": "All ({count})",
        "custom_label": "Customize Scan Target Range",
        "btn_submit": "Execute Audit",
        "loading_title": "Scanning Network Activities",
        "loading_sub": "Geolocating nodes and checking threat intelligence. Please wait.",
        "loading_host": "Checking host: {ip}",
        "loading_progress": "{current} of {total} nodes processed",
        "map_isp_title": "Your Internet Provider (IP Gateway)",
        "map_precise_title": "Your Precise Location",
        "map_browser_source": "Retrieved via browser",
        "map_popup_process": "Process",
        "map_popup_ip": "IP",
        "map_popup_hostname": "Hostname",
        "map_popup_lport": "Local Port",
        "map_popup_status": "Status",
        "map_popup_isp": "Provider",
        "map_popup_as": "AS",
        "map_popup_loc": "Location",
        "map_popup_score": "Threat Score",
        "map_popup_factors": "Factors",
        "lang_btn": "RU",
        "map_panel_title": "Filter Panel",
        "map_panel_search_lbl": "Search (process, IP, city)",
        "map_panel_score_lbl": "Min Threat Score",
        "map_panel_score_all": "All Scores",
        "map_panel_stats_total": "Total",
        "map_panel_stats_max_score": "Max Score",
        "dash_net_title": "Gateway & Environment",
        "dash_net_ip": "External IP",
        "dash_net_isp": "ISP Gateway",
        "dash_net_loc": "Geo Gateway",
        "dash_net_platform": "Local Platform",
        "dash_net_ports": "TCP Port Scans",
        "dash_control_title": "Scan Engine",
        "dash_control_desc": "Initiate network topography map generation and security analysis."
    },
    "ru": {
        "title": "Сетевой Командный Центр Угроз",
        "badge": "Активные Сокеты",
        "btn_5": "Лимит 5",
        "btn_10": "Лимит 10",
        "btn_15": "Лимит 15",
        "btn_all": "Все ({count})",
        "custom_label": "Настройка диапазона сканирования",
        "btn_submit": "Запустить Аудит",
        "loading_title": "Сканирование Сети",
        "loading_sub": "Определение геолокации и проверка баз репутации. Пожалуйста, подождите.",
        "loading_host": "Проверка хоста: {ip}",
        "loading_progress": "Обработано {current} из {total} узлов",
        "map_isp_title": "Ваш интернет-провайдер (IP Gateway)",
        "map_precise_title": "Ваше точное местоположение",
        "map_browser_source": "Получено через браузер",
        "map_popup_process": "Процесс",
        "map_popup_ip": "IP",
        "map_popup_hostname": "Имя хоста",
        "map_popup_lport": "Локальный порт",
        "map_popup_status": "Статус",
        "map_popup_isp": "Провайдер",
        "map_popup_as": "AS",
        "map_popup_loc": "Местоположение",
        "map_popup_score": "Оценка угрозы",
        "map_popup_factors": "Факторы",
        "lang_btn": "EN",
        "map_panel_title": "Панель фильтрации",
        "map_panel_search_lbl": "Поиск (процесс, IP, город)",
        "map_panel_score_lbl": "Мин. угроза",
        "map_panel_score_all": "Все уровни",
        "map_panel_stats_total": "Всего",
        "map_panel_stats_max_score": "Макс. угроза",
        "dash_net_title": "Шлюз и Окружение",
        "dash_net_ip": "Внешний IP",
        "dash_net_isp": "ISP Провайдер",
        "dash_net_loc": "Гео-локация",
        "dash_net_platform": "Локальная ОС",
        "dash_net_ports": "TCP Порты",
        "dash_control_title": "Консоль Управления",
        "dash_control_desc": "Запуск картографирования соединений и оценки уровня угроз."
    }
}

def get_port_color(port):
    if port == 443:
        return "green"
    elif port == 80:
        return "orange"
    elif port in [22, 3389]:
        return "blue"
    elif port in [8080, 8443]:
        return "purple"
    return "red"

def fetch_ip_worker(ip):
    geo = get_geolocation(ip)
    return ip, geo

def run_scan_thread(limit):
    global SCAN_STATE
    SCAN_STATE["status"] = "scanning"
    SCAN_STATE["current"] = 0
    SCAN_STATE["current_ip"] = ""
    SCAN_STATE["local_geo"] = {}
    SCAN_STATE["remote_data"] = []
    
    local_geo = get_geolocation() or {
        "lat": 0.0, "lon": 0.0, "city": "Unknown", "country": "Unknown", 
        "query": "127.0.0.1", "isp": "Unknown", "org": "Unknown", "as": "Unknown"
    }
    SCAN_STATE["local_geo"] = local_geo

    active_conns = get_connections()
    unique_ips = list(set(conn["ip"] for conn in active_conns))[:limit]
    SCAN_STATE["total"] = len(unique_ips)

    cache = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_ip_worker, ip): ip for ip in unique_ips}
        for index, future in enumerate(futures, 1):
            ip = futures[future]
            SCAN_STATE["current"] = index
            SCAN_STATE["current_ip"] = ip
            try:
                resolved_ip, geo = future.result()
                if geo:
                    cache[resolved_ip] = geo
            except Exception:
                pass

    remote_data = []
    for conn in active_conns:
        ip = conn["ip"]
        if ip in cache:
            geo = cache[ip]
            isp = geo.get("isp", "Unknown")
            org = geo.get("org", "Unknown")
            as_num = geo.get("as", "Unknown")
            
            score, factors = evaluate_reputation(ip, isp, org, conn.get("process_path", ""))
            color = get_port_color(conn["remote_port"])
            
            remote_data.append({
                "ip": ip,
                "process": conn["process"],
                "local_port": conn["local_port"],
                "remote_port": conn["remote_port"],
                "status": conn["status"],
                "lat": geo.get("lat", 0.0),
                "lon": geo.get("lon", 0.0),
                "city": geo.get("city", "Unknown"),
                "country": geo.get("country", "Unknown"),
                "isp": isp,
                "as": as_num,
                "score": score,
                "factors": factors,
                "color": color,
                "hostname": geo.get("hostname", "Unknown")
            })
            
    SCAN_STATE["remote_data"] = remote_data
    SCAN_STATE["status"] = "complete"

class VisualizerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global CURRENT_LANG
        parsed_path = urlparse(self.path)
        
        if parsed_path.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            
            active_conns = get_connections()
            unique_ips = list(set(conn["ip"] for conn in active_conns))
            total_conns = len(unique_ips)
            local_ports_count = len(active_conns)
            local_platform = platform.system() + " " + platform.release()

            local_geo = get_geolocation() or {
                "lat": 0.0, "lon": 0.0, "city": "Unknown", "country": "Unknown", 
                "query": "127.0.0.1", "isp": "Unknown", "org": "Unknown", "as": "Unknown"
            }

            labels = TRANSLATIONS[CURRENT_LANG]

            home_html = """<!DOCTYPE html>
<html>
<head>
    <title>Network Threat Intelligence Visualizer</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-color: #0a0c14;
            color: #c9d1d9;
            box-sizing: border-box;
            padding: 40px 20px;
        }
        .dashboard-header {
            max-width: 960px;
            width: 100%;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .dashboard-header h1 {
            color: #58a6ff;
            margin: 0;
            font-size: 20px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .btn-lang {
            background-color: #161b22;
            color: #58a6ff;
            border: 1px solid #30363d;
            padding: 6px 12px;
            font-size: 12px;
            font-weight: bold;
            border-radius: 4px;
            text-decoration: none;
        }
        .dashboard-layout {
            display: flex;
            gap: 24px;
            max-width: 960px;
            width: 100%;
        }
        .column-side { flex: 1; }
        .column-main { flex: 1.2; }
        .card {
            background-color: #161b22;
            border-radius: 12px;
            border: 1px solid #30363d;
            padding: 24px;
            box-sizing: border-box;
        }
        .card h3 {
            margin-top: 0;
            margin-bottom: 18px;
            font-size: 13px;
            color: #8b949e;
            text-transform: uppercase;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
        }
        .telemetry-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 15px;
        }
        .telemetry-label { font-size: 13px; color: #8b949e; }
        .telemetry-value { font-size: 14px; font-weight: 600; color: #f0f6fc; font-family: monospace; }
        .highlight-blue { color: #58a6ff; }
        .pulse-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            border: 2px solid #388bfd;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            margin: 0 auto 25px auto;
            background-color: rgba(56, 139, 253, 0.05);
        }
        .pulse-number { font-size: 32px; font-weight: bold; color: #f0f6fc; font-family: monospace; }
        .pulse-label { font-size: 10px; color: #8b949e; text-transform: uppercase; margin-top: 4px; }
        .profiles-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 20px; }
        .btn-profile {
            background-color: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 8px 4px;
            font-size: 11px;
            border-radius: 6px;
            text-decoration: none;
            text-align: center;
            font-weight: 600;
        }
        .control-slider { width: 100%; }
        .btn-execute {
            display: block;
            width: 100%;
            background-color: #238636;
            color: white;
            border: 1px solid #2ea44f;
            padding: 14px;
            font-size: 14px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            text-transform: uppercase;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <h1>__TITLE__</h1>
        <a href="/toggle_lang" class="btn-lang">__LANG_BTN__</a>
    </div>

    <div class="dashboard-layout">
        <div class="column-side">
            <div class="card">
                <h3>__LABEL_NET_TITLE__</h3>
                <div class="telemetry-row" style="margin-top:0;">
                    <div class="telemetry-label">__LABEL_NET_IP__</div>
                    <div class="telemetry-value highlight-blue">__LOCAL_IP__</div>
                </div>
                <div class="telemetry-row">
                    <div class="telemetry-label">__LABEL_NET_ISP__</div>
                    <div class="telemetry-value">__LOCAL_ISP__</div>
                </div>
                <div class="telemetry-row">
                    <div class="telemetry-label">__LABEL_NET_LOC__</div>
                    <div class="telemetry-value">__LOCAL_CITY__, __LOCAL_COUNTRY__</div>
                </div>
                <div class="telemetry-row">
                    <div class="telemetry-label">__LABEL_NET_PLATFORM__</div>
                    <div class="telemetry-value">__LOCAL_PLATFORM__</div>
                </div>
                <div class="telemetry-row">
                    <div class="telemetry-label">__LABEL_NET_PORTS__</div>
                    <div class="telemetry-value highlight-blue">__LOCAL_PORTS__</div>
                </div>
            </div>
        </div>

        <div class="column-main">
            <div class="card">
                <h3>__LABEL_CONTROL_TITLE__</h3>
                <div class="pulse-circle">
                    <div class="pulse-number">__TOTAL_CONNS__</div>
                    <div class="pulse-label">__BADGE__</div>
                </div>
                <div class="profiles-grid">
                    <a href="/scan?limit=5" class="btn-profile">__BTN_5__</a>
                    <a href="/scan?limit=10" class="btn-profile">__BTN_10__</a>
                    <a href="/scan?limit=15" class="btn-profile">__BTN_15__</a>
                    <a href="/scan?limit=__TOTAL_CONNS__" class="btn-profile">__BTN_ALL_RAW__</a>
                </div>
                <form action="/scan" method="get">
                    <div style="margin: 20px 0;">
                        <span id="slider-text-lbl">__CUSTOM_LABEL__</span>: <span id="slider-val" class="highlight-blue">10</span>
                        <input type="range" name="limit" min="1" max="__TOTAL_CONNS__" value="10" class="control-slider" oninput="document.getElementById('slider-val').innerText = this.value">
                    </div>
                    <button type="submit" class="btn-execute">__BTN_SUBMIT__</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>"""
            home_html = home_html.replace("__TITLE__", labels["title"])
            home_html = home_html.replace("__BADGE__", labels["badge"])
            home_html = home_html.replace("__BTN_5__", labels["btn_5"])
            home_html = home_html.replace("__BTN_10__", labels["btn_10"])
            home_html = home_html.replace("__BTN_15__", labels["btn_15"])
            home_html = home_html.replace("__BTN_ALL_RAW__", labels["btn_all"].replace(" ({count})", ""))
            home_html = home_html.replace("__CUSTOM_LABEL__", labels["custom_label"])
            home_html = home_html.replace("__BTN_SUBMIT__", labels["btn_submit"])
            home_html = home_html.replace("__LANG_BTN__", labels["lang_btn"])
            home_html = home_html.replace("__TOTAL_CONNS__", str(total_conns if total_conns > 0 else 1))
            home_html = home_html.replace("__LABEL_NET_TITLE__", labels["dash_net_title"])
            home_html = home_html.replace("__LABEL_NET_IP__", labels["dash_net_ip"])
            home_html = home_html.replace("__LABEL_NET_ISP__", labels["dash_net_isp"])
            home_html = home_html.replace("__LABEL_NET_LOC__", labels["dash_net_loc"])
            home_html = home_html.replace("__LABEL_NET_PLATFORM__", labels["dash_net_platform"])
            home_html = home_html.replace("__LABEL_NET_PORTS__", labels["dash_net_ports"])
            home_html = home_html.replace("__LABEL_CONTROL_TITLE__", labels["dash_control_title"])
            home_html = home_html.replace("__LOCAL_IP__", str(local_geo.get("query", "Unknown")))
            home_html = home_html.replace("__LOCAL_ISP__", str(local_geo.get("isp", "Unknown")))
            home_html = home_html.replace("__LOCAL_CITY__", str(local_geo.get("city", "Unknown")))
            home_html = home_html.replace("__LOCAL_COUNTRY__", str(local_geo.get("country", "Unknown")))
            home_html = home_html.replace("__LOCAL_PLATFORM__", str(local_platform))
            home_html = home_html.replace("__LOCAL_PORTS__", str(local_ports_count))

            self.wfile.write(home_html.encode("utf-8"))
            
        elif parsed_path.path == "/toggle_lang":
            CURRENT_LANG = "ru" if CURRENT_LANG == "en" else "en"
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            
        elif parsed_path.path == "/scan":
            query_params = parse_qs(parsed_path.query)
            limit = 10
            if "limit" in query_params:
                try:
                    limit = int(query_params["limit"][0])
                except ValueError:
                    pass
            
            if SCAN_STATE["status"] != "scanning":
                thread = threading.Thread(target=run_scan_thread, args=(limit,))
                thread.start()
                
            self.send_response(303)
            self.send_header("Location", "/loading")
            self.end_headers()
            
        elif parsed_path.path == "/loading":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            labels = TRANSLATIONS[CURRENT_LANG]
            
            loading_html = """<!DOCTYPE html>
<html>
<head>
    <title>Scanning...</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #0d1117;
            color: #c9d1d9;
        }
        .container {
            background-color: #161b22;
            padding: 40px;
            border-radius: 12px;
            border: 1px solid #30363d;
            text-align: center;
            max-width: 480px;
            width: 100%;
        }
        h1 { color: #58a6ff; margin-top: 0; font-size: 24px; }
        .progress-container {
            width: 100%;
            background-color: #0d1117;
            border-radius: 10px;
            height: 10px;
            overflow: hidden;
            margin: 25px 0;
            border: 1px solid #30363d;
        }
        .progress-fill {
            height: 100%;
            background-color: #388bfd;
            width: 0%;
            transition: width 0.2s ease;
        }
        .host-display { color: #58a6ff; font-size: 14px; font-family: monospace; }
        .progress-text { color: #8b949e; font-size: 13px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>__TITLE__</h1>
        <div class="progress-container">
            <div class="progress-fill" id="fill"></div>
        </div>
        <div class="host-display" id="host"></div>
        <div class="progress-text" id="progress-text"></div>
    </div>
    <script>
        var labels = __LABELS_DATA__;
        function updateStatus() {
            fetch('/api/status')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    if (data.status === 'scanning') {
                        var percent = data.total > 0 ? (data.current / data.total) * 100 : 0;
                        document.getElementById('fill').style.width = percent + '%';
                        document.getElementById('host').innerText = data.current_ip ? labels.loading_host.replace('{ip}', data.current_ip) : '';
                        document.getElementById('progress-text').innerText = labels.loading_progress.replace('{current}', data.current).replace('{total}', data.total);
                    } else if (data.status === 'complete') {
                        window.location.href = '/map';
                    }
                });
        }
        setInterval(updateStatus, 300);
    </script>
</body>
</html>"""
            loading_html = loading_html.replace("__TITLE__", labels["loading_title"])
            loading_html = loading_html.replace("__LABELS_DATA__", json.dumps(labels))
            self.wfile.write(loading_html.encode("utf-8"))
            
        elif parsed_path.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(SCAN_STATE).encode("utf-8"))
            
        elif parsed_path.path == "/map":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            
            html_content = HTML_TEMPLATE.replace("__LOCAL_GEO_DATA__", json.dumps(SCAN_STATE["local_geo"]))
            html_content = html_content.replace("__CONNECTIONS_DATA__", json.dumps(SCAN_STATE["remote_data"]))
            html_content = html_content.replace("__LABELS_DATA__", json.dumps(TRANSLATIONS[CURRENT_LANG]))
            
            self.wfile.write(html_content.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def main():
    server_address = (SERVER_HOST, SERVER_PORT)
    httpd = HTTPServer(server_address, VisualizerHandler)
    url = f"http://localhost:{SERVER_PORT}/"
    print(f"Server started at {url}")
    webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

if __name__ == "__main__":
    main()