"""
app_vulnerable.py
=================
Servidor web DIDÁCTICO e INTENCIONALMENTE VULNERABLE a SQL Injection.

Uso exclusivo en laboratorio (localhost). NO desplegar en ningún servidor real.
Vulnerabilidad: las consultas SQL se construyen CONCATENANDO la entrada del
usuario (f-strings), lo que permite alterar la lógica de la consulta.

Ejecución:  python app_vulnerable.py      ->  http://127.0.0.1:5000
"""
import os
import sqlite3

from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "usuarios.db")


# ----------------------------------------------------------------------------
# Base de datos de prueba (SQLite)
# ----------------------------------------------------------------------------
def init_db():
    """Crea la base de datos con datos ficticios (contraseñas en texto plano
    a propósito, para mostrar el impacto de la extracción de registros)."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL
        );
        INSERT INTO users (username, password, role) VALUES
            ('admin',  'Adm1n_S3cret!', 'administrador'),
            ('maria',  'maria2026',    'usuario'),
            ('carlos', 'carlos#123',   'usuario'),
            ('juan', 'juan2026',   'usuario');
        INSERT INTO products (name, price) VALUES
            ('Laptop',   750.00),
            ('Mouse',     15.50),
            ('Teclado',   32.00),
            ('Monitor',  180.00);
        """
    )
    con.commit()
    con.close()


# ----------------------------------------------------------------------------
# Plantilla HTML mínima
# ----------------------------------------------------------------------------
PAGE = """
<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>{{ title }}</title>
<style>
 body{font-family:Arial;max-width:760px;margin:30px auto;padding:0 12px}
 .banner{background:#b71c1c;color:#fff;padding:8px 12px;border-radius:6px}
 input{padding:6px;margin:4px 0;width:260px} button{padding:7px 14px}
 pre{background:#f4f4f4;padding:10px;border-radius:6px;white-space:pre-wrap}
 table{border-collapse:collapse} td,th{border:1px solid #999;padding:4px 8px}
 .ok{color:#1b5e20;font-weight:bold} .err{color:#b71c1c;font-weight:bold}
</style></head><body>
<div class="banner">⚠ VERSIÓN VULNERABLE (solo laboratorio) — SQL Injection</div>
<h2>{{ title }}</h2>
<p><a href="/">Login</a> | <a href="/buscar">Buscar productos</a></p>
{{ body|safe }}
</body></html>
"""


def render(title, body):
    return render_template_string(PAGE, title=title, body=body)


# ----------------------------------------------------------------------------
# Rutas
# ----------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    form = """
    <form method="post">
      Usuario:<br><input name="username"><br>
      Contraseña:<br><input name="password" type="password"><br>
      <button type="submit">Ingresar</button>
    </form>"""
    if request.method == "GET":
        return render("Inicio de sesión", form)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # ===== VULNERABILIDAD: concatenación insegura de cadenas =====
    query = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    # =============================================================
    info = f"<p>Consulta ejecutada:</p><pre>{query}</pre>"

    try:
        con = sqlite3.connect(DB_PATH)
        row = con.execute(query).fetchone()
        con.close()
    except sqlite3.Error as e:
        # Error detallado expuesto al cliente (mala práctica, facilita el ataque)
        return render("Inicio de sesión", form + info + f"<p class='err'>Error SQL: {e}</p>"), 500

    if row:
        msg = f"<p class='ok'>ACCESO CONCEDIDO — Bienvenido {row[1]} (rol: {row[2]})</p>"
        return render("Inicio de sesión", form + info + msg), 200
    return render("Inicio de sesión", form + info + "<p class='err'>ACCESO DENEGADO</p>"), 401


@app.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    form = """
    <form method="get">
      Producto: <input name="q"> <button type="submit">Buscar</button>
    </form>"""
    if not q:
        return render("Búsqueda de productos", form)

    # ===== VULNERABILIDAD: concatenación insegura de cadenas =====
    query = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
    # =============================================================
    info = f"<p>Consulta ejecutada:</p><pre>{query}</pre>"

    try:
        con = sqlite3.connect(DB_PATH)
        rows = con.execute(query).fetchall()
        con.close()
    except sqlite3.Error as e:
        return render("Búsqueda de productos", form + info + f"<p class='err'>Error SQL: {e}</p>"), 500

    tabla = "<table><tr><th>ID</th><th>Nombre</th><th>Precio</th></tr>"
    for r in rows:
        tabla += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>"
    tabla += "</table>"
    return render("Búsqueda de productos", form + info + tabla), 200


if __name__ == "__main__":
    init_db()
    # host=127.0.0.1: solo accesible desde la propia máquina
    app.run(host="127.0.0.1", port=5000, debug=False)
