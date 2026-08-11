import sys
import argparse
import config
from main import main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Threat Intelligence Visualizer")
    parser.add_argument("--host", type=str, default=config.SERVER_HOST, help="Server host address")
    parser.add_argument("--port", type=int, default=config.SERVER_PORT, help="Server port number")
    parser.add_argument("--no-browser", action="store_true", help="Disable automatic browser launch")
    args = parser.parse_args()

    config.SERVER_HOST = args.host
    config.SERVER_PORT = args.port

    try:
        main(open_browser=not args.no_browser)
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user.")
        sys.exit(0)