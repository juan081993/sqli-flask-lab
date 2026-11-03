"""
hardening_bd.py
===============
Auditoría básica y endurecimiento (hardening) de una base de datos SQLite.

Uso:
    python hardening_bd.py --db usuarios.db              # solo auditar
    python hardening_bd.py --db usuarios.db --migrar     # migrar contraseñas a hash
"""
import argparse
import os
import shutil
import sqlite3
import stat
import sys
from datetime import datetime

from werkzeug.security import generate_password_hash


def es_hash(valor):
    return isinstance(valor, str) and valor.startswith(("pbkdf2:", "scrypt:", "argon2"))


def auditar(db):
    hallazgos = []
    con = sqlite3.connect(db)

    # 1. Permisos del archivo (en Linux/Mac; en Windows se omite)
    if os.name == "posix":
        modo = stat.S_IMODE(os.stat(db).st_mode)
        if modo & (stat.S_IRWXG | stat.S_IRWXO):
            hallazgos.append(("ALTO", f"Archivo con permisos amplios ({oct(modo)}). Recomendado 0o600"))
        else:
            hallazgos.append(("OK", f"Permisos del archivo restringidos ({oct(modo)})"))

    # 2. Integridad
    res = con.execute("PRAGMA integrity_check").fetchone()[0]
    hallazgos.append(("OK" if res == "ok" else "ALTO", f"Integridad de la BD: {res}"))

    # 3. Claves foráneas
    fk = con.execute("PRAGMA foreign_keys").fetchone()[0]
    hallazgos.append(("OK" if fk else "MEDIO", "Claves foráneas " + ("activas" if fk else "desactivadas (activar con PRAGMA foreign_keys=ON)")))

    # 4. Contraseñas en texto plano
    cols = [c[1] for c in con.execute("PRAGMA table_info(users)")]
    if "password" in cols:
        filas = con.execute("SELECT username, password FROM users").fetchall()
        planas = [u for u, p in filas if not es_hash(p)]
        if planas:
            hallazgos.append(("CRÍTICO", f"{len(planas)} contraseña(s) en texto plano: {', '.join(planas)}"))
        else:
            hallazgos.append(("OK", "Todas las contraseñas están hasheadas"))
    elif "password_hash" in cols:
        hallazgos.append(("OK", "La tabla usa la columna password_hash"))

    con.close()
    return hallazgos


def migrar_a_hash(db):
    """Respalda la BD y reemplaza contraseñas en texto plano por hashes."""
    respaldo = f"{db}.bak_{datetime.now():%Y%m%d_%H%M%S}"
    shutil.copy2(db, respaldo)
    print(f"[+] Respaldo creado: {respaldo}")
    con = sqlite3.connect(db)
    filas = con.execute("SELECT id, password FROM users").fetchall()
    n = 0
    for id_, pw in filas:
        if not es_hash(pw):
            con.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(pw), id_))
            n += 1
    con.commit()
    con.close()
    print(f"[+] {n} contraseña(s) migradas a hash")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="usuarios.db")
    ap.add_argument("--migrar", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        sys.exit(f"[!] No existe {args.db}. Ejecute primero app_vulnerable.py")

    print(f"=== Auditoría de {args.db} ===")
    for nivel, msg in auditar(args.db):
        print(f"[{nivel:<7}] {msg}")

    if args.migrar:
        print("\n=== Aplicando hardening ===")
        migrar_a_hash(args.db)
        if os.name == "posix":
            os.chmod(args.db, 0o600)
            print("[+] Permisos del archivo establecidos en 0o600")
        print("\n=== Auditoría posterior ===")
        for nivel, msg in auditar(args.db):
            print(f"[{nivel:<7}] {msg}")

    print("\nBuenas prácticas: mínimo privilegio, respaldos cifrados, consultas "
          "parametrizadas, hashing con sal, errores genéricos y registro de accesos.")


if __name__ == "__main__":
    main()
