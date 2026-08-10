import sys
from main import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user.")
        sys.exit(0)