# Network Threat Intelligence Visualizer

An interactive network topography and threat intelligence visualizer written in Python and JavaScript. It inspects active TCP socket connections on the host machine, geolocates remote endpoints, calculates threat levels using multi-source DNSBL and process location heuristics, and renders an interactive dark-mode map using Leaflet.js.

## Features

- **Live Socket Inspection**: Real-time analysis of system TCP connections via `psutil`.
- **Live Auto-Refresh Mode**: Dynamic map updates every 5 seconds without page reloading.
- **Process Bandwidth I/O Tracking**: Displays real-time read and write data bytes for each active process.
- **Parallel Scanning Engine**: Asynchronous multi-threaded lookup architecture using `ThreadPoolExecutor`.
- **Geographic Topography**: Map plotting with Leaflet & CartoDB Dark Matter tiles.
- **Threat Intelligence Scoring**: Calculates threat scores based on Hosting/Datacenter networks, DNSBL blocklists (Barracuda, SpamCop, SORBS), and untrusted process directories.
- **SQLite Smart Cache**: TTL-cached GeoIP results to prevent external rate limits and speed up subsequent scans.
- **CSV Report Export**: One-click threat audit report generator.
- **Dual Language UI**: English / Russian support.

## Installation

```bash
git clone https://github.com/d3fuse99/NetThreatVis.git
cd NetThreatVis
pip install -r requirements.txt