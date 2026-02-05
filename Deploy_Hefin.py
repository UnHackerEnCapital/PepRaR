# -*- coding: utf-8 -*-
import os
import subprocess
import sys

# --- CONFIGURACIÓN DE LOS ARCHIVOS ---

CREDS_CONTENT = """
# Archivo de credenciales dinámico
ADMIN_USER = "rrhh"
ADMIN_PASS = "hefin1234"
"""

APP_CONTENT = r"""# -*- coding: utf-8 -*-
import os
import subprocess
import importlib
from flask import Flask, render_template_string, request

import creds

app = Flask(__name__)
app.secret_key = "hefin_cyber_security_key"
UPLOAD_FOLDER = 'uploads'

# Ruta al ejecutable de WinRAR (GUI/Proceso principal)
WINRAR_EXE = r"C:\Program Files\WinRAR\WinRAR.exe"

PUESTOS = ['SOC_Analyst', 'Pentester_Offensive', 'Blue_Team_Defensive', 'Cloud_Engineer', 'Forensics_TIF']

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
for p in PUESTOS:
    os.makedirs(os.path.join(UPLOAD_FOLDER, p), exist_ok=True)

# --- INTERFAZ ---
# --- INTERFAZ ---
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Hefin.io | Recruitment Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Roboto+Mono:wght@300;400&display=swap" rel="stylesheet">
    <style>
        :root { --primary: #00ff41; --bg: #050505; --card-bg: rgba(20, 20, 20, 0.8); --border: rgba(0, 255, 65, 0.3); }
        body { background-color: var(--bg); color: #e0e0e0; font-family: 'Rajdhani', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
        .container { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 40px; width: 100%; max-width: 650px; text-align: center; }
        h1 { color: var(--primary); letter-spacing: 3px; }
        .form-group { text-align: left; margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: var(--primary); }
        input, select { width: 100%; padding: 12px; background: rgba(0,0,0,0.5); border: 1px solid var(--border); color: white; box-sizing: border-box; }
        button { width: 100%; padding: 15px; background: transparent; border: 1px solid var(--primary); color: var(--primary); cursor: pointer; font-weight: 700; margin-top: 10px; }
        button:hover { background: var(--primary); color: black; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; text-align: left; }
        th { border-bottom: 2px solid var(--primary); padding: 12px; color: var(--primary); background: rgba(0,255,65,0.05); }
        td { padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.1); font-size: 0.85rem; }
    </style>
</head>
<body>
    <div class="container">
        {% if mode == "index" %}
            <h1>HEFIN.IO</h1>
            <p>[ SECURE CAREER PORTAL ]</p>
            <form action="/postular" method="post" enctype="multipart/form-data">
                <div class="form-group">
                    <label>IDENTIDAD</label>
                    <input type="text" name="nombre" placeholder="Nombre completo" required>
                </div>
                <div class="form-group">
                    <label>OPERACION / PUESTO</label>
                    <select name="puesto">
                        {% for p in puestos %}<option value="{{p}}">{{p}}</option>{% endfor %}
                    </select>
                </div>
                <div class="form-group">
                    <label>EXPEDIENTE (.RAR)</label>
                    <input type="file" name="archivo" accept=".rar" required>
                </div>
                <button type="submit">SUBIR POSTULACION</button>
            </form>
        {% elif mode == "rrhh" %}
            <h1 style="text-shadow: 0 0 10px #ff0000; color: #ff3333;">INTERNAL DATABASE</h1>
            {% if not logueado %}
                <p style="color: #ff3333; font-family: 'Roboto Mono';">[ ACCESO RESTRINGIDO: NIVEL 5 ]</p>
                <form method="post">
                    <input type="text" name="user" placeholder="OPERATOR_ID" required><br><br>
                    <input type="password" name="pass" placeholder="SECRET_TOKEN" required><br><br>
                    <button type="submit" style="border-color: #ff3333; color: #ff3333;">DESBLOQUEAR TERMINAL</button>
                </form>
            {% else %}
                <div style="background: rgba(0, 255, 65, 0.1); border: 1px solid var(--primary); padding: 10px; margin-bottom: 20px; font-family: 'Roboto Mono'; font-size: 0.8rem; text-align: left;">
                    <span style="color: var(--primary);">[+] STATUS: ACCESO TOTAL CONCEDIDO</span><br>
                    <span style="color: var(--primary);">[+] PRIVILEGIOS: ADMINISTRADOR DEL MULTIVERSO</span><br>
                    <span style="color: #888;">[!] ADVERTENCIA: TODA ACTIVIDAD ESTÁ SIENDO MONITOREADA POR HEFINSITA</span>
                </div>
                
                <table>
                    <tr>
                        <th>OPERACIÓN</th>
                        <th>IDENTIDAD</th>
                        <th>DATOS SENSIBLES (EXFILTRADOS)</th>
                    </tr>
                    <tr style="color: #ffb86c;">
                        <td>Red_Team</td>
                        <td>El_Pepe_Original</td>
                        <td>IP: 192.168.1.105 | SSH_KEY: RSA-4096 | OBS: "Ete Sech"</td>
                    </tr>
                    <tr style="color: #ffb86c;">
                        <td>Cyber_Intelligence</td>
                        <td>Hefinsita_Fan_1</td>
                        <td>DNI: 20-44123123-2 | PASS: admin1234 (REUTILIZADA)</td>
                    </tr>
                    {% for puesto, lista in data.items() %}
                        {% for c in lista %}
                        <tr>
                            <td style="color: var(--primary);">{{ puesto }}</td>
                            <td>{{ c }}</td>
                            <td style="font-family: 'Roboto Mono'; font-size: 0.7rem; color: #666;">
                                VOL: C:\\Users\\Nahuel\\Downloads\\... | STATUS: PENDING_REVIEW
                            </td>
                        </tr>
                        {% endfor %}
                    {% endfor %}
                </table>
                <br><a href="/" style="color: #ff3333; text-decoration: none; font-family: 'Roboto Mono'; font-size: 0.8rem;">[ CERRAR SESIÓN Y LIMPIAR LOGS ]</a>
            {% endif %}
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE, mode="index", puestos=PUESTOS)

@app.route('/postular', methods=['POST'])
def postular():
    nombre = request.form.get('nombre').replace(" ", "_")
    puesto = request.form.get('puesto')
    archivo = request.files['archivo']
    if archivo and archivo.filename.endswith('.rar'):
        ruta_candidato = os.path.abspath(os.path.join(UPLOAD_FOLDER, puesto, nombre))
        os.makedirs(ruta_candidato, exist_ok=True)
        rar_path = os.path.join(ruta_candidato, "temp.rar")
        archivo.save(rar_path)
        
        try:
            # Comando de WinRAR para extraer (x), modo silencioso/background (-ibck)
            # Esto emula la extracción manual por GUI
            subprocess.run([
                WINRAR_EXE, 
                "x",          # Extraer con rutas completas
                "-ibck",      # Ejecutar en segundo plano (sin ventana emergente molesta)
                "-y",         # Decir 'Sí' a todo (sobrescribir si es necesario)
                rar_path, 
                "*.*", 
                ruta_candidato + os.sep
            ], check=True)
            
            os.remove(rar_path)
            return render_template_string(HTML_TEMPLATE, mode="index", puestos=PUESTOS) + "<script>alert('Postulacion enviada con exito');</script>"
        except Exception as e:
            return f"Error en la extracción (Asegúrate de que WinRAR esté instalado): {e}"
    return "Formato invalido."

@app.route('/rrhh', methods=['GET', 'POST'])
def rrhh():
    importlib.reload(creds)
    logueado = False
    data = {}
    if request.method == 'POST':
        if request.form.get('user') == creds.ADMIN_USER and request.form.get('pass') == creds.ADMIN_PASS:
            logueado = True
            for p in PUESTOS:
                if os.path.exists(os.path.join(UPLOAD_FOLDER, p)):
                    data[p] = os.listdir(os.path.join(UPLOAD_FOLDER, p))
    return render_template_string(HTML_TEMPLATE, mode="rrhh", logueado=logueado, data=data)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
"""

def deploy():
    print("--- DESPLIEGUE HEFIN.IO (MODO WINRAR GUI) ---")
    
    # Crear entorno virtual si no existe
    if not os.path.exists('venv'):
        subprocess.run([sys.executable, "-m", "venv", "venv"])
    
    # Instalar Flask
    pip_exe = os.path.join('venv', 'Scripts', 'pip.exe')
    subprocess.run([pip_exe, "install", "flask"])

    # Crear archivos necesarios
    if not os.path.exists('creds.py'):
        with open('creds.py', 'w', encoding='utf-8') as f:
            f.write(CREDS_CONTENT.strip())

    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(APP_CONTENT.strip())

    # Ejecutar el servidor
    python_venv = os.path.join('venv', 'Scripts', 'python.exe')
    print("\n[*] Servidor configurado para usar la lógica de WinRAR GUI.")
    print("[*] Accede a http://localhost:5000")
    subprocess.run([python_venv, "app.py"])

if __name__ == "__main__":
    deploy()