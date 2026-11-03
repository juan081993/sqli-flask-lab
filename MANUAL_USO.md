# Manual de Uso y Pruebas

## 1. Requisitos

- Python 3.9 o superior
- Visual Studio Code (o cualquier editor)
- Git (opcional, para subir al repositorio)

## 2. Instalación

```bash
# (Opcional) entorno virtual
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux / Mac

pip install -r requirements.txt
```

## 3. Fase 1 — Ataque a la aplicación vulnerable

1. Inicie el servidor vulnerable:
   ```bash
   python app_vulnerable.py
   ```
2. Abra `http://127.0.0.1:5000` en el navegador.
3. **Prueba manual en el login** (📸 capture cada una):

   | Usuario | Contraseña | Resultado esperado |
   |---|---|---|
   | `maria` | `maria2026` | Acceso concedido (uso legítimo) |
   | `' OR '1'='1' --` | `x` | Acceso concedido sin credenciales (bypass) |
   | `admin'--` | `x` | Entra como admin sin contraseña |
   | `'` | `x` | Error SQL expuesto |

4. **Prueba manual en la búsqueda** (`/buscar`):

   | Entrada | Resultado esperado |
   |---|---|
   | `Mouse` | 1 producto |
   | `' OR '1'='1` | Toda la tabla |
   | `zzz' UNION SELECT id, username \|\| ':' \|\| password, 0 FROM users --` | Usuarios y contraseñas filtrados |

5. **Prueba automatizada** (en otra terminal):
   ```bash
   python ataque_sql_i.py --url http://127.0.0.1:5000 --etiqueta ANTES
   ```
   Genera `resultados_antes.csv`.

## 4. Fase 2 — Validación de la mitigación

1. Detenga el servidor vulnerable (`Ctrl + C`) o déjelo corriendo (usa otro puerto).
2. Inicie la versión segura:
   ```bash
   python app_segura.py
   ```
3. Repita las mismas pruebas manuales en `http://127.0.0.1:5001` (📸 capturas).
4. Ejecute el script automatizado:
   ```bash
   python ataque_sql_i.py --url http://127.0.0.1:5001 --etiqueta DESPUES
   ```
   Genera `resultados_despues.csv`.

**Resultado esperado:** todos los payloads son tratados como texto simple; los controles legítimos siguen funcionando.

## 5. Módulos complementarios

### 5.1 Escaneo de red (puertos/servicios)
```bash
python escaneo_red.py                                # puertos comunes en 127.0.0.1
python escaneo_red.py --host 127.0.0.1 --ports 1-1024
python escaneo_red.py --ports 5000,5001
```
Con los servidores en ejecución deben aparecer abiertos los puertos 5000 y/o 5001.

### 5.2 Hardening de la base de datos
```bash
python hardening_bd.py --db usuarios.db              # auditoría
python hardening_bd.py --db usuarios.db --migrar     # aplica hash a contraseñas + respaldo
```
> Ejecute la auditoría con `app_vulnerable.py` iniciado al menos una vez (se crea `usuarios.db`).
> Nota: `--migrar` modifica `usuarios.db`; reinicie `app_vulnerable.py` para regenerar los datos originales.

## 6. Capturas recomendadas para el informe

1. Servidor vulnerable en ejecución (terminal).
2. Login con bypass `' OR '1'='1' --` exitoso (mostrando la consulta ejecutada).
3. Extracción UNION con usuarios y contraseñas.
4. Salida de `ataque_sql_i.py` ANTES.
5. Servidor seguro en ejecución.
6. Mismos payloads rechazados en la versión segura.
7. Salida de `ataque_sql_i.py` DESPUÉS.
8. Salida de `escaneo_red.py` y `hardening_bd.py`.

## 7. Solución de problemas

| Problema | Solución |
|---|---|
| `No module named flask` | `pip install -r requirements.txt` |
| `Address already in use` | Cierre el proceso previo o cambie el puerto en `app.run(...)` |
| El ataque no conecta | Verifique que el servidor esté corriendo en otra terminal |

## 8. Subir al repositorio GitHub

```bash
git init
git add .
git commit -m "Práctica 4: SQL Injection con Flask"
git branch -M main
git remote add origin https://github.com/USUARIO/REPO.git
git push -u origin main
```
Agregue un `.gitignore` con `*.db`, `__pycache__/`, `venv/` y `resultados_*.csv`.
