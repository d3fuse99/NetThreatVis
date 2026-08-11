HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Network Threat Intelligence Visualizer</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
    <style>
        html, body {
            margin: 0;
            padding: 0;
            height: 100%;
            width: 100%;
            background-color: #0d1117;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .map-container {
            height: 100%;
            width: 100%;
        }
        @keyframes flow {
            to {
                stroke-dashoffset: -20;
            }
        }
        .flow-line {
            stroke-dasharray: 8, 8;
            animation: flow 1s linear infinite;
        }
        .marker-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            border: 2px solid #ffffff;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
        }
        .dot-green { background-color: #2ea44f; box-shadow: 0 0 10px #2ea44f; }
        .dot-yellow { background-color: #d29922; box-shadow: 0 0 10px #d29922; }
        .dot-red { background-color: #f85149; box-shadow: 0 0 10px #f85149; }
        .control-panel {
            position: absolute;
            top: 20px;
            right: 20px;
            z-index: 1000;
            background-color: rgba(22, 27, 34, 0.95);
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
            width: 270px;
            color: #c9d1d9;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.6);
        }
        .control-panel h3 {
            margin-top: 0;
            margin-bottom: 12px;
            font-size: 14px;
            color: #58a6ff;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid #30363d;
            padding-bottom: 8px;
        }
        .control-group {
            margin-bottom: 12px;
        }
        .control-group label {
            display: block;
            font-size: 11px;
            color: #8b949e;
            margin-bottom: 5px;
        }
        .control-input, .control-select {
            width: 100%;
            background-color: #0d1117;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 6px 10px;
            font-size: 12px;
            border-radius: 4px;
            box-sizing: border-box;
            outline: none;
        }
        .live-box {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background-color: #0d1117;
            border: 1px solid #30363d;
            padding: 8px 10px;
            border-radius: 4px;
            margin-bottom: 12px;
            font-size: 12px;
            color: #2ea44f;
            font-weight: bold;
        }
        .stats-box {
            font-size: 11px;
            color: #8b949e;
            border-top: 1px solid #30363d;
            margin-top: 10px;
            padding-top: 8px;
            display: flex;
            justify-content: space-between;
        }
        .stats-val {
            color: #58a6ff;
            font-weight: bold;
        }
        .btn-export {
            display: block;
            width: 100%;
            background-color: #21262d;
            color: #c9d1d9;
            border: 1px solid #30363d;
            padding: 8px;
            font-size: 11px;
            font-weight: bold;
            border-radius: 4px;
            cursor: pointer;
            text-align: center;
            margin-top: 8px;
            transition: all 0.2s;
        }
        .btn-export:hover {
            background-color: #30363d;
            color: #58a6ff;
        }
        .btn-kill {
            background-color: #da3633;
            color: white;
            border: none;
            padding: 4px 8px;
            font-size: 10px;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 6px;
            font-weight: bold;
        }
        .btn-kill:hover {
            background-color: #f85149;
        }
    </style>
</head>
<body>
    <div class="map-container" id="map-element"></div>
    
    <div class="control-panel">
        <h3 id="panel-title"></h3>
        <div class="live-box">
            <span>Live Refresh (5s)</span>
            <input type="checkbox" id="live-toggle" onchange="toggleLiveMode(this)">
        </div>
        <div class="control-group">
            <label id="search-label" for="search-input"></label>
            <input type="text" id="search-input" class="control-input" onkeyup="applyFilters()">
        </div>
        <div class="control-group">
            <label id="score-label" for="score-filter"></label>
            <select id="score-filter" class="control-select" onchange="applyFilters()">
                <option value="0" id="opt-all"></option>
                <option value="30">&ge; 30</option>
                <option value="50">&ge; 50</option>
                <option value="70">&ge; 70</option>
            </select>
        </div>
        <div class="stats-box">
            <div><span id="stat-total-label"></span>: <span id="stat-total-val" class="stats-val">0</span></div>
            <div><span id="stat-max-label"></span>: <span id="stat-max-val" class="stats-val">0</span></div>
        </div>
        <button class="btn-export" onclick="exportCSV()">Export CSV Report</button>
        <button class="btn-export" onclick="exportJSON()">Export JSON Report</button>
    </div>

    <script>
        var localGeo = __LOCAL_GEO_DATA__;
        var connections = __CONNECTIONS_DATA__;
        var labels = __LABELS_DATA__;

        var localLat = localGeo.lat || 0.0;
        var localLon = localGeo.lon || 0.0;
        var elements = [];
        var liveInterval = null;

        document.getElementById('panel-title').innerText = labels.map_panel_title;
        document.getElementById('search-label').innerText = labels.map_panel_search_lbl;
        document.getElementById('score-label').innerText = labels.map_panel_score_lbl;
        document.getElementById('opt-all').innerText = labels.map_panel_score_all;
        document.getElementById('stat-total-label').innerText = labels.map_panel_stats_total;
        document.getElementById('stat-max-label').innerText = labels.map_panel_stats_max_score;

        var map = L.map(document.getElementById('map-element')).setView([localLat, localLon], 3);
        
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OpenStreetMap &copy; CARTO',
            subdomains: 'abcd',
            maxZoom: 20
        }).addTo(map);

        function escapeHtml(text) {
            if (!text) return "";
            return String(text)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        }

        function copyKillCmd(pid) {
            var cmd = "taskkill /F /PID " + pid;
            navigator.clipboard.writeText(cmd).then(function() {
                alert("Kill command copied: " + cmd);
            });
        }

        var safeLocalQuery = escapeHtml(localGeo.query);
        var safeLocalIsp = escapeHtml(localGeo.isp);
        var safeLocalAs = escapeHtml(localGeo.as);
        var safeLocalCity = escapeHtml(localGeo.city);
        var safeLocalCountry = escapeHtml(localGeo.country);
        var localFlag = localGeo.flag || "🌐";

        var ispMarker = L.marker([localLat, localLon]).addTo(map);
        ispMarker.bindPopup("<b>" + labels.map_isp_title + "</b><br>" +
                             "<b>IP:</b> " + (safeLocalQuery || "Unknown") + "<br>" +
                             "<b>" + labels.map_popup_isp + ":</b> " + (safeLocalIsp || "Unknown") + "<br>" +
                             "<b>" + labels.map_popup_as + ":</b> " + (safeLocalAs || "Unknown") + "<br>" +
                             "<b>" + labels.map_popup_loc + ":</b> " + localFlag + " " + (safeLocalCity || "Unknown") + ", " + (safeLocalCountry || "Unknown"));

        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(function(position) {
                var preciseLat = position.coords.latitude;
                var preciseLon = position.coords.longitude;
                
                var preciseMarker = L.marker([preciseLat, preciseLon], {
                    icon: L.divIcon({
                        className: 'precise-marker-icon',
                        html: '<div style="background-color: #388bfd; width: 12px; height: 12px; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 10px #388bfd;"></div>',
                        iconSize: [12, 12]
                    })
                }).addTo(map);
                preciseMarker.bindPopup("<b>" + labels.map_precise_title + "</b><br>" + labels.map_browser_source).openPopup();
                
                L.polyline([[preciseLat, preciseLon], [localLat, localLon]], {
                    color: 'gray',
                    weight: 1.5,
                    dashArray: '5, 5'
                }).addTo(map);

                var bounds = L.latLngBounds([[preciseLat, preciseLon], [localLat, localLon]]);
                map.fitBounds(bounds);
            }, function() {
                ispMarker.openPopup();
            });
        } else {
            ispMarker.openPopup();
        }

        var maxThreatScore = 0;

        function addConnectionToMap(conn) {
            var dotClass = 'dot-green';
            if (conn.score >= 60) {
                dotClass = 'dot-red';
            } else if (conn.score >= 30) {
                dotClass = 'dot-yellow';
            }

            var customIcon = L.divIcon({
                className: 'custom-dot-icon',
                html: '<div class="marker-dot ' + dotClass + '"></div>',
                iconSize: [12, 12]
            });

            var remoteMarker = L.marker([conn.lat, conn.lon], { icon: customIcon }).addTo(map);
            var factorsText = conn.factors.map(escapeHtml).join('<br>&bull; ');
            
            var safeProcess = escapeHtml(conn.process);
            var safeIp = escapeHtml(conn.ip);
            var safeHostname = escapeHtml(conn.hostname);
            var safeIsp = escapeHtml(conn.isp);
            var safeAs = escapeHtml(conn.as);
            var safeCity = escapeHtml(conn.city);
            var safeCountry = escapeHtml(conn.country);
            var safeStatus = escapeHtml(conn.status);
            var safeIoRead = escapeHtml(conn.io_read || "0 B");
            var safeIoWrite = escapeHtml(conn.io_write || "0 B");
            var flag = conn.flag || "🌐";
            var pid = conn.pid || 0;

            if (conn.score > maxThreatScore) {
                maxThreatScore = conn.score;
            }

            var popupContent = "<b>" + labels.map_popup_process + ":</b> " + safeProcess + " (PID: " + pid + ")<br>" +
                               "<b>" + labels.map_popup_ip + ":</b> " + safeIp + " (" + conn.remote_port + ")<br>" +
                               "<b>" + labels.map_popup_hostname + ":</b> " + safeHostname + "<br>" +
                               "<b>Traffic I/O:</b> R: " + safeIoRead + " | W: " + safeIoWrite + "<br>" +
                               "<b>" + labels.map_popup_lport + ":</b> " + conn.local_port + "<br>" +
                               "<b>" + labels.map_popup_status + ":</b> " + safeStatus + "<br>" +
                               "<b>" + labels.map_popup_isp + ":</b> " + safeIsp + "<br>" +
                               "<b>" + labels.map_popup_as + ":</b> " + safeAs + "<br>" +
                               "<b>" + labels.map_popup_loc + ":</b> " + flag + " " + safeCity + ", " + safeCountry + "<br>" +
                               "<b>" + labels.map_popup_score + ":</b> " + conn.score + "/100<br>" +
                               "<b>" + labels.map_popup_factors + ":</b><br>&bull; " + factorsText + "<br>" +
                               "<button class='btn-kill' onclick='copyKillCmd(" + pid + ")'>Copy Taskkill Command</button>";

            remoteMarker.bindPopup(popupContent);

            var line = L.polyline([
                [localLat, localLon],
                [conn.lat, conn.lon]
            ], {
                color: conn.color,
                weight: 2,
                opacity: 0.7,
                className: 'flow-line'
            }).addTo(map);
            
            line.bindPopup(popupContent);

            elements.push({
                marker: remoteMarker,
                line: line,
                process: conn.process,
                ip: conn.ip,
                city: conn.city,
                score: conn.score,
                data: conn
            });
        }

        connections.forEach(function(conn) {
            addConnectionToMap(conn);
        });

        document.getElementById('stat-total-val').innerText = elements.length;
        document.getElementById('stat-max-val').innerText = maxThreatScore;

        function applyFilters() {
            var searchText = document.getElementById('search-input').value.toLowerCase();
            var minScore = parseInt(document.getElementById('score-filter').value) || 0;
            var visibleCount = 0;

            elements.forEach(function(item) {
                var matchesSearch = item.process.toLowerCase().includes(searchText) || 
                                    item.ip.toLowerCase().includes(searchText) || 
                                    item.city.toLowerCase().includes(searchText);
                var matchesScore = item.score >= minScore;

                if (matchesSearch && matchesScore) {
                    visibleCount++;
                    if (!map.hasLayer(item.marker)) {
                        item.marker.addTo(map);
                        item.line.addTo(map);
                    }
                } else {
                    if (map.hasLayer(item.marker)) {
                        map.removeLayer(item.marker);
                        map.removeLayer(item.line);
                    }
                }
            });

            document.getElementById('stat-total-val').innerText = visibleCount;
        }

        function toggleLiveMode(checkbox) {
            if (checkbox.checked) {
                liveInterval = setInterval(fetchLiveUpdates, 5000);
                fetchLiveUpdates();
            } else {
                if (liveInterval) clearInterval(liveInterval);
            }
        }

        function fetchLiveUpdates() {
            fetch('/api/live')
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    if (data && data.remote_data) {
                        elements.forEach(function(item) {
                            map.removeLayer(item.marker);
                            map.removeLayer(item.line);
                        });
                        elements = [];
                        maxThreatScore = 0;
                        connections = data.remote_data;

                        connections.forEach(function(conn) {
                            addConnectionToMap(conn);
                        });
                        
                        applyFilters();
                        document.getElementById('stat-max-val').innerText = maxThreatScore;
                    }
                });
        }

        function exportCSV() {
            var csvRows = ["Process,PID,Remote IP,Remote Port,Local Port,Status,Read Bytes,Written Bytes,Country,City,ISP,Threat Score"];
            connections.forEach(function(c) {
                var row = [
                    '"' + c.process + '"',
                    c.pid || 0,
                    '"' + c.ip + '"',
                    c.remote_port,
                    c.local_port,
                    '"' + c.status + '"',
                    '"' + (c.io_read || "0 B") + '"',
                    '"' + (c.io_write || "0 B") + '"',
                    '"' + c.country + '"',
                    '"' + c.city + '"',
                    '"' + c.isp + '"',
                    c.score
                ];
                csvRows.push(row.join(","));
            });
            var blob = new Blob([csvRows.join("\\n")], { type: 'text/csv' });
            var url = window.URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.setAttribute('href', url);
            a.setAttribute('download', 'network_threat_report.csv');
            a.click();
        }

        function exportJSON() {
            var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(connections, null, 2));
            var a = document.createElement('a');
            a.setAttribute('href', dataStr);
            a.setAttribute('download', 'network_threat_report.json');
            a.click();
        }
    </script>
</body>
</html>"""