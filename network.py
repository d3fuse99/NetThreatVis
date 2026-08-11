import ipaddress
import psutil

def is_valid_remote(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False

def format_bytes(bytes_num):
    if not bytes_num:
        return "0 B"
    num = float(bytes_num)
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"

def get_connections():
    connections = []
    try:
        conns = psutil.net_connections(kind="tcp")
    except Exception:
        conns = []
        
    for conn in conns:
        if conn.raddr:
            ip = conn.raddr.ip
            if is_valid_remote(ip):
                proc_name = "Unknown"
                proc_path = ""
                pid = conn.pid or 0
                io_read = "0 B"
                io_write = "0 B"
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                        proc_path = p.exe()
                        io = p.io_counters()
                        io_read = format_bytes(io.read_bytes)
                        io_write = format_bytes(io.write_bytes)
                    except Exception:
                        pass
                connections.append({
                    "ip": ip,
                    "pid": pid,
                    "process": proc_name,
                    "process_path": proc_path,
                    "remote_port": conn.raddr.port,
                    "local_port": conn.laddr.port,
                    "status": conn.status,
                    "io_read": io_read,
                    "io_write": io_write
                })
    return connections