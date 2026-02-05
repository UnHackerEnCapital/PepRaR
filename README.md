# PepRaR
# 🐸 PepRaR – WinRAR Path Traversal Lab & PoC (CVE-2025-8088 & 2025-6218)

<img width="290" height="263" alt="PepRaR" src="https://github.com/user-attachments/assets/d2ceac11-d2fb-4b68-a427-3e9f06def06c" />

Bienvenido a **PepRaR**, un entorno de laboratorio desarrollado para **validar y explotar de forma controlada** las vulnerabilidades de **Path Traversal** e **Inyeccion de Codigo Remoto** en WinRAR descubiertas en 2025. 

Este proyecto recrea un escenario real donde un atacante puede sobrescribir archivos críticos del sistema mediante la descompresión de un archivo malicioso, logrando en este caso el compromiso de un portal de reclutamiento de ciberseguridad.

> 🔐 **Aviso:** Este laboratorio debe ejecutarse en una **instancia de Windows virtualizada o controlada**, ya que realiza modificaciones en el sistema de archivos local para demostrar la PoC.

Los identificadores CVE asociados son:
- **CVE-2025-8088**
- **CVE-2025-6218**

---

### ⚠️ Condiciones de la Vulnerabilidad

Es importante tener en cuenta que este vector de ataque no es universal y requiere condiciones específicas para ser exitoso:

* **Sistemas Afectados:** Únicamente sistemas operativos **Windows**.
* **Versiones de WinRAR:** Afecta a versiones **7.12 o anteriores** (se recomienda la versión incluida en este repo para la PoC).
* **Modo de Extracción:** El exploit solo es efectivo en extracciones realizadas mediante la **interfaz gráfica (GUI)**. Las extracciones por línea de comandos suelen ignorar el vector de Path Traversal utilizado en esta técnica.

> 📁 **Nota:** En la carpeta `/bin` de este repositorio, se encuentra el instalador de la versión exacta de WinRAR utilizada en este laboratorio para garantizar que puedas replicar los resultados.

---
---
<br>

## 🔍 ¿Qué es este laboratorio?

<br>

El laboratorio se divide en dos componentes principales:

1. 🏢 **Hefin.io Portal (Deploy_Hefin.py):** Levanta un servidor Flask local (Puerto 5000) que simula un portal de RRHH. El portal permite subir "Expedientes (.rar)" que son procesados automáticamente por el motor de WinRAR en el servidor.
2. 🐸 **PepRaR (PepRaR.py):** Script de generación de exploits que aprovecha las vulnerabilidades de WinRAR para embeber un payload de Path Traversal dentro de un archivo comprimido.

---

<br>

## ⚙️ ¿Cómo funciona la PoC?
<br>

La explotación se basa en la sobrescritura de archivos lógicos del servidor:

1. **Reconocimiento:** Se identifica que el portal guarda los archivos en una ruta conocida y utiliza un archivo de configuración llamado `creds.py` para validar el acceso al área administrativa.
2. **Generación:** `PepeGe.py` genera un archivo `PepRaR.rar`. Este archivo contiene un payload diseñado para "saltar" del directorio de subida y sobrescribir `creds.py` con nuevas credenciales (pepe / pepe1234).
3. **Explotación:** Al subir el archivo al portal, el servidor invoca a WinRAR para extraerlo. Debido a la vulnerabilidad, el archivo se deposita fuera del área segura, reemplazando el archivo de credenciales original.
4. **Acceso:** El atacante ahora puede ingresar al `/rrhh` con el nuevo usuario y contraseña, obteniendo **Acceso Total**.

---
<br>

## 📸 Guía de Explotación

<br>

### 1️⃣ Levantar el Laboratorio
Ejecuta el script de despliegue en tu instancia de Windows:

![deploy](https://github.com/user-attachments/assets/a5a7e0b4-1753-4093-af53-c6c73fef7f56)

```bash
python Deploy_Hefin.py
```
<br>

### Credenciales por Defecto de Acceso 
<br>

<img width="482" height="126" alt="Captura de pantalla 2026-02-04 215204" src="https://github.com/user-attachments/assets/233151bc-3e51-4db6-8da8-864189c2519f" />

```bash
Archivo creds.py generado por el Deploy, aca se almacenan las credenciales de acceso.
```
<br>

### 2️⃣ Generar el Archivo Malicioso
<br>
<br>
En una nueva terminal, ejecutamos el script generador para crear el archivo `.rar` con el payload de **Path Traversal**:

![Exploit](https://github.com/user-attachments/assets/ed0044c9-946c-42c7-b34c-93bf28965a7a)

 
```bash
python PepRaR.py
```

> 💡 Esto creará un archivo llamado `PepRaR.rar` que contiene la instrucción para sobrescribir `creds.py` al ser extraído.
 
 ---
<br>

 ### 3️⃣ Ejecutar la Inyección
 1. Accede al portal en tu navegador: `http://localhost:5000`
 2. Ve a la sección de **"Envío de CV / Expedientes"**.
 3. Sube el archivo `PepRaR.rar` generado anteriormente.
 4. El servidor procesará el archivo automáticamente usando WinRAR.
 
 ---
 <br>

 ### 4️⃣ Compromiso del Sistema
 Una vez subido, intenta acceder al panel de administración:
 * **URL:** `http://localhost:5000/rrhh`
 * **Usuario:** `pepe`
 * **Password:** `pepe1234`
 
 Si el acceso es exitoso, habrás validado la vulnerabilidad de **escritura arbitraria de archivos**.
 
 <img width="288" height="99" alt="Captura de pantalla 2026-02-04 215124" src="https://github.com/user-attachments/assets/74c93da7-bad7-4eca-bf3c-bea9efd33002" />

 ---
 <br>
 
## 🧑‍💻 Créditos e Inspiración

Este script generador ha sido modificado e inspirado en el excelente trabajo de investigación disponible en:
🔗 [https://github.com/pentestfunctions/best-CVE-2025-8088](https://github.com/pentestfunctions/best-CVE-2025-8088)

<br>

Damos los créditos correspondientes a los investigadores originales por el descubrimiento y la documentación de este vector de ataque.
 ---
 <br>

 ## 🛠️ Requisitos
 * **Sistema Operativo:** Windows 10/11 (VM Recomendada).
 * **Python 3.x** instalado.
 * **WinRAR** (Versión vulnerable < 7.02).
 * Librerías de Python:
     ```bash
     pip install flask
     ```
<br>


> [!IMPORTANT]
> **Entorno de Prueba:** Este laboratorio ha sido testeado y se recomienda ejecutarlo en **Windows Server 2019**. 
> Podés descargar la imagen de evaluación oficial desde el sitio de Microsoft:
> 🔗 [Windows Server 2019 Evaluation Center](https://www.microsoft.com/es-es/evalcenter/download-windows-server-2019)

---
 <br>

 ## ⚠️ Descargo de Responsabilidad
 > Esta herramienta se proporciona exclusivamente con fines educativos y de investigación para validar la seguridad de sistemas frente a los **CVE-2025-8088** y **CVE-2025-6218**. El autor no se responsabiliza por usos indebidos fuera de entornos controlados.
 <br>

 ---
 **Adaptado por Hefin.net** – 2026
