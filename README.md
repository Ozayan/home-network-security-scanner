# Home Network Security Scanner

Aplicação educacional em Python com interface gráfica para inventariar dispositivos que expõem serviços TCP comuns em uma rede local privada.

## Funcionalidades

- detecta automaticamente uma sugestão de rede local `/24`;
- aceita somente IPv4 privado e limita o scan a 256 endereços;
- testa portas comuns sem depender do Nmap;
- tenta identificar hostname e serviço;
- classifica resultados como **OK**, **Atenção** ou **Revisar**;
- permite interromper o scan;
- exporta relatórios em CSV e JSON;
- mantém a interface responsiva usando execução em segundo plano.

> Use somente em redes próprias ou para as quais você tenha autorização explícita.

## Requisitos

- Python 3.10 ou superior
- Windows, Linux ou macOS

## Instalação

```bash
git clone https://github.com/Ozayan/home-network-security-scanner.git
cd home-network-security-scanner
python -m venv .venv
```

No Windows:

```powershell
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

No Linux/macOS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Como funciona

O programa usa `ipaddress` para validar a rede, `socket` para testar conexões TCP e `ThreadPoolExecutor` para verificar endereços em paralelo. Um dispositivo aparece na tabela quando pelo menos uma das portas monitoradas responde.

Portas verificadas: `21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 631, 3389, 5900, 8008, 8080`.

Uma porta aberta não significa, por si só, que existe uma vulnerabilidade. A classificação apenas indica serviços que merecem revisão no contexto da rede doméstica.

## Testes

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Estrutura

```text
home-network-security-scanner/
├── app.py
├── scanner/
│   ├── discovery.py
│   ├── risk_analyzer.py
│   └── services.py
├── ui/
│   └── main_window.py
├── tests/
├── reports/
├── requirements.txt
└── README.md
```

## Ideias para evolução

- descoberta via ARP para listar hosts sem portas abertas;
- consulta local de fabricante pelo endereço MAC;
- histórico em SQLite;
- seleção personalizada de portas;
- empacotamento em `.exe` com PyInstaller.

## Licença

MIT.
