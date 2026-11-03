# Laboratorio de SQL Injection — Flask + SQLite

**Asignatura:** Seguridad Informática · **Carrera:** Tecnologías de la Información (en línea) · **UNEMI** · 2026

Proyecto educativo que demuestra cómo una **concatenación insegura de cadenas SQL** permite un ataque de
*SQL Injection* (OWASP Top 10 — A03: Injection) y cómo se neutraliza con **consultas parametrizadas**.

> ⚠️ **Aviso ético:** `app_vulnerable.py` es vulnerable a propósito. Úselo únicamente en `localhost`
> y con fines académicos. Los scripts rechazan objetivos que no sean locales/privados.

## Contenido

| Archivo | Descripción |
|---|---|
| `app_vulnerable.py` | Servidor Flask vulnerable (login y búsqueda) — puerto 5000 |
| `ataque_sql_i.py` | Script de pruebas con payloads controlados (bypass y extracción) |
| `app_segura.py` | Versión mitigada: consultas parametrizadas + hash de contraseñas — puerto 5001 |
| `escaneo_red.py` | Escáner básico de puertos TCP (solo loopback / red privada) |
| `hardening_bd.py` | Auditoría y endurecimiento de la base de datos SQLite |
| `MANUAL_USO.md` | Guía paso a paso |
| `requirements.txt` | Dependencias |

## Inicio rápido

```bash
pip install -r requirements.txt
python app_vulnerable.py          # terminal 1
python ataque_sql_i.py --url http://127.0.0.1:5000 --etiqueta ANTES   # terminal 2
python app_segura.py              # terminal 1 (tras detener la anterior, o en otra terminal)
python ataque_sql_i.py --url http://127.0.0.1:5001 --etiqueta DESPUES
```

## Contramedidas demostradas

- Sentencias preparadas (`?`) en lugar de f-strings.
- Contraseñas con hash y sal (`werkzeug.security`).
- Mensajes de error genéricos y sin exponer la consulta.
- Validación de longitud de entrada.
- Principio de mínimo privilegio, permisos de archivo y respaldos (`hardening_bd.py`).

## Referencias

- OWASP. *SQL Injection Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- Pallets Projects. *Flask Documentation*. https://flask.palletsprojects.com/
- McClure, S. (2010). *Hackers 6: Secretos y soluciones de seguridad en redes*. McGraw-Hill.

## Autores

- Diego Armando Ayala Armijos
- Lizbeth Verónica Casco Bastidas
- Marcello Radamés Cordero Torrealba
- Jennifer Ariana Farias Rojas
- Juan Carlos Pillasagua Alcívar
- Wilson Javier Quishpe Toaquiza
- Griselda Coraima Rúa Bailón

