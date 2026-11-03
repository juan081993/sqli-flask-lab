"""
escaneo_red.py
==============
Escáner básico de puertos TCP (connect scan) para el laboratorio.

Restricción ética: solo permite objetivos de loopback o redes privadas
(127.0.0.0/8, 10/8, 172.16/12, 192.168/16). Escanear equipos ajenos sin
autorización es ilegal.

Uso:
    python escaneo_red.py                          # 127.0.0.1, puertos comunes
    python escaneo_red.py --host 127.0.0.1 --ports 1-1024
    python escaneo_red.py --host 127.0.0.1 --ports 5000,5001,22,80
"""
import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

PUERTOS_COMUNES = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445,
                   1433, 3306, 3389, 5000, 5001, 5432, 8000, 8080]


def validar_host(host):
    """Resuelve el host y verifica que sea loopback o privado."""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except (socket.gaierror, ValueError):
        sys.exit(f"[!] No se pudo resolver el host '{host}'")
    if not (ip.is_loopback or ip.is_private):
        sys.exit(f"[!] {ip} no es una dirección local/privada. Escaneo no permitido.")
    return str(ip)


def parsear_puertos(texto):
    puertos = set()
    for parte in texto.split(","):
        parte = parte.strip()
        if "-" in parte:
            a, b = parte.split("-")
            puertos.update(range(int(a), int(b) + 1))
        elif parte:
            puertos.add(int(parte))
    return sorted(p for p in puertos if 1 <= p <= 65535)


def escanear_puerto(ip, puerto, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip, puerto)) == 0:
            try:
                servicio = socket.getservbyport(puerto, "tcp")
            except OSError:
                servicio = "desconocido"
            return puerto, servicio
    return None


def main():
    ap = argparse.ArgumentParser(description="Escáner de puertos básico (solo local)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--ports", default=None, help="Ej: 1-1024 o 22,80,5000")
    args = ap.parse_args()

    ip = validar_host(args.host)
    puertos = parsear_puertos(args.ports) if args.ports else PUERTOS_COMUNES

    print(f"[*] Escaneando {ip} ({len(puertos)} puertos)...\n")
    with ThreadPoolExecutor(max_workers=100) as ex:
        resultados = [r for r in ex.map(lambda p: escanear_puerto(ip, p), puertos) if r]

    print(f"{'PUERTO':<10}{'ESTADO':<10}{'SERVICIO'}")
    print("-" * 36)
    for puerto, servicio in resultados:
        print(f"{puerto:<10}{'abierto':<10}{servicio}")
    if not resultados:
        print("(ningún puerto abierto en el rango)")
    print(f"\n[+] {len(resultados)} puerto(s) abierto(s).")
    print("[i] Recomendación: cierre los servicios que no necesite y use un "
          "cortafuegos (ej. ufw / Windows Defender Firewall) con política de "
          "denegar por defecto.")


if __name__ == "__main__":
    main()
