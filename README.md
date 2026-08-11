# Network Threat Intelligence Visualizer

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Docker Support](https://img.shields.io/badge/docker-ready-blue.svg)

An interactive network topography and threat intelligence visualizer written in Python and JavaScript. It inspects active TCP socket connections on the host machine, geolocates remote endpoints, calculates threat levels using multi-source DNSBL and process location heuristics, and renders an interactive dark-mode map using Leaflet.js.

## Features

- **Live Socket Inspection**: Real-time analysis of system TCP connections via `psutil`.
- **Live Auto-Refresh Mode**: Dynamic map updates every 5 seconds without page reloading.
- **Process Bandwidth I/O Tracking**: Displays real-time read and write data bytes for each active process.
- **Batch GeoIP Lookup**: High-speed batch processing via ip-api.com API.
- **Country Flags & PID Telemetry**: Displays national flags and process PID with quick taskkill command copy.
- **CLI Configuration**: Support for custom host, port, and headless browser options.
- **Geographic Topography**: Map plotting with Leaflet & CartoDB Dark Matter tiles.
- **Threat Intelligence Scoring**: Calculates threat scores based on Hosting/Datacenter networks, DNSBL blocklists, and untrusted process directories.
- **SQLite Smart Cache**: TTL-cached GeoIP results to prevent external rate limits.
- **CSV & JSON Report Export**: One-click threat audit report generator.
- **Containerization**: Full Docker support included.
- **Dual Language UI**: English / Russian UI support.

## Tech Stack

- Python 3.8+
- SQLite3
- Leaflet.js / CartoDB Dark Tiles
- psutil

## Installation & Setup

1. Clone the repository:

```bash
git clone https://github.com/d3fuse99/NetThreatVis.git
cd NetThreatVis
```

2. Install required dependencies:

```bash
pip install -r requirements.txt
```

3. Launch the application:

```bash
python visualizer.py
```

### CLI Options

```bash
python visualizer.py --port 8080 --host 127.0.0.1 --no-browser
```

### Docker Deployment

```bash
docker build -t netthreatvis .
docker run -d -p 8000:8000 netthreatvis
```

## License

Distributed under the MIT License.
