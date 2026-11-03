"""
app_segura.py
=============
Versión MITIGADA de app_vulnerable.py.

Contramedidas aplicadas:
  1. Consultas parametrizadas (sentencias preparadas con '?').
  2. Contraseñas almacenadas con hash (werkzeug.security) en lugar de texto plano.
  3. Mensajes de error genéricos (sin exponer detalles del motor SQL).
  4. No se muestra la consulta ejecutada al cliente.
  5. Validación básica de longitud/tipo de la entrada (defensa en profundidad).

Ejecución:  python app_segura.py      ->  http://127.0.0.1:5001
"""
import os
import sqlite3

from flask import Flask, request, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "usuarios_seguro.db")
MAX_LEN = 50


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL
        );
        """
    )
    usuarios = [
        ("admin", "Adm1n_S3cret!", "administrador"),
        ("maria", "maria2026", "usuario"),
        ("carlos", "carlos#123", "usuario"),
        ("juan", "juan2026", "usuario"),
    ]
    # Consulta parametrizada también al insertar
    con.executemany(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        [(u, generate_password_hash(p), r) for u, p, r in usuarios],
    )
    con.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [("Laptop", 750.0), ("Mouse", 15.5), ("Teclado", 32.0), ("Monitor", 180.0)],
    )
    con.commit()
    con.close()


PAGE = """
<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>{{ title }}</title>
<style>
 body{font-family:Arial;max-width:760px;margin:30px auto;padding:0 12px}
 .banner{background:#1b5e20;color:#fff;padding:8px 12px;border-radius:6px}
 input{padding:6px;margin:4px 0;width:260px} button{padding:7px 14px}
 table{border-collapse:collapse} td,th{border:1px solid #999;padding:4px 8px}
 .ok{color:#1b5e20;font-weight:bold} .err{color:#b71c1c;font-weight:bold}
</style></head><body>
<div class="banner">✔ VERSIÓN SEGURA — consultas parametrizadas</div>
<h2>{{ title }}</h2>
<p><a href="/">Login</a> | <a href="/buscar">Buscar productos</a></p>
{{ body|safe }}
</body></html>
"""


def render(title, body):
    return render_template_string(PAGE, title=title, body=body)


@app.route("/", methods=["GET", "POST"])
def login():
    form = """
    <form method="post">
      Usuario:<br><input name="username" maxlength="50"><br>
      Contraseña:<br><input name="password" type="password" maxlength="50"><br>
      <button type="submit">Ingresar</button>
    </form>"""
    if request.method == "GET":
        return render("Inicio de sesión", form)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password or len(username) > MAX_LEN or len(password) > MAX_LEN:
        return render("Inicio de sesión", form + "<p class='err'>Credenciales inválidas</p>"), 400

    try:
        con = sqlite3.connect(DB_PATH)
        # ===== CONTRAMEDIDA: consulta parametrizada =====
        row = con.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        # ================================================
        con.close()
    except sqlite3.Error:
        return render("Inicio de sesión", form + "<p class='err'>Error interno</p>"), 500

    if row and check_password_hash(row[2], password):
        msg = f"<p class='ok'>ACCESO CONCEDIDO — Bienvenido {row[1]} (rol: {row[3]})</p>"
        return render("Inicio de sesión", form + msg), 200
    return render("Inicio de sesión", form + "<p class='err'>ACCESO DENEGADO</p>"), 401


@app.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    form = """
    <form method="get">
      Producto: <input name="q" maxlength="50"> <button type="submit">Buscar</button>
    </form>"""
    if not q:
        return render("Búsqueda de productos", form)
    if len(q) > MAX_LEN:
        return render("Búsqueda de productos", form + "<p class='err'>Entrada demasiado larga</p>"), 400

    try:
        con = sqlite3.connect(DB_PATH)
        # ===== CONTRAMEDIDA: el comodín se agrega al PARÁMETRO, no a la sentencia =====
        rows = con.execute(
            "SELECT id, name, price FROM products WHERE name LIKE ?",
            (f"%{q}%",),
        ).fetchall()
        # ===============================================================================
        con.close()
    except sqlite3.Error:
        return render("Búsqueda de productos", form + "<p class='err'>Error interno</p>"), 500

    tabla = "<table><tr><th>ID</th><th>Nombre</th><th>Precio</th></tr>"
    for r in rows:
        tabla += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>"
    tabla += "</table>"
    if not rows:
        tabla = "<p>Sin resultados.</p>"
    return render("Búsqueda de productos", form + tabla), 200


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)
