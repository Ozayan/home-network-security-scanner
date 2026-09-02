import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from .risk_analyzer import analyze_ports
from .services import COMMON_PORTS, service_name


def validate_private_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("Informe uma rede CIDR válida, como 192.168.1.0/24.") from exc
    if network.version != 4 or not network.is_private:
        raise ValueError("Por segurança, somente redes IPv4 privadas são permitidas.")
    if network.num_addresses > 256:
        raise ValueError("Use uma sub-rede com no máximo 256 endereços (/24 ou menor).")
    return network


def detect_local_network() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        local_ip = sock.getsockname()[0]
        return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except OSError:
        return "192.168.1.0/24"
    finally:
        sock.close()


def _is_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def scan_host(ip: str, ports: list[int], timeout: float = 0.25) -> dict | None:
    open_ports = [port for port in ports if _is_open(ip, port, timeout)]
    if not open_ports:
        return None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = "Não identificado"
    status, findings = analyze_ports(open_ports)
    return {
        "ip": ip,
        "hostname": hostname,
        "open_ports": open_ports,
        "services": [service_name(p) for p in open_ports],
        "status": status,
        "findings": findings,
    }


def scan_network(network_text: str, progress=None, stop_event=None) -> list[dict]:
    network = validate_private_network(network_text)
    hosts = [str(ip) for ip in network.hosts()]
    ports = list(COMMON_PORTS)
    results = []
    with ThreadPoolExecutor(max_workers=min(64, max(1, len(hosts)))) as pool:
        futures = {pool.submit(scan_host, ip, ports): ip for ip in hosts}
        for done, future in enumerate(as_completed(futures), 1):
            if stop_event and stop_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
            result = future.result()
            if result:
                results.append(result)
            if progress:
                progress(done, len(hosts), result)
    return sorted(results, key=lambda item: ipaddress.ip_address(item["ip"]))
