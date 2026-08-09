import ipaddress
import psutil

def is_valid_remote(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False

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
                if conn.pid:
                    try:
                        p = psutil.Process(conn.pid)
                        proc_name = p.name()
                        proc_path = p.exe()
                    except Exception:
                        pass
                connections.append({
                    "ip": ip,
                    "process": proc_name,
                    "process_path": proc_path,
                    "remote_port": conn.raddr.port,
                    "local_port": conn.laddr.port,
                    "status": conn.status
                })
    return connections