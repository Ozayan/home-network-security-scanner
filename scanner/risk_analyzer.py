RISKY_PORTS = {
    21: ("FTP transmite credenciais sem criptografia", "Atenção"),
    23: ("Telnet transmite dados sem criptografia", "Revisar"),
    139: ("NetBIOS exposto na rede", "Atenção"),
    445: ("SMB deve ser restrito a dispositivos confiáveis", "Atenção"),
    3389: ("RDP deve usar autenticação forte e acesso restrito", "Atenção"),
    5900: ("VNC deve estar protegido e atualizado", "Atenção"),
}


def analyze_ports(open_ports: list[int]) -> tuple[str, list[str]]:
    findings = [RISKY_PORTS[p][0] for p in open_ports if p in RISKY_PORTS]
    if 23 in open_ports:
        return "Revisar", findings
    if findings:
        return "Atenção", findings
    return "OK", []
