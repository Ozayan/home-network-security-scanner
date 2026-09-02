COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 443: "HTTPS",
    445: "SMB", 631: "IPP", 3389: "RDP", 5900: "VNC",
    8008: "HTTP alternativo", 8080: "HTTP alternativo",
}


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "Desconhecido")
