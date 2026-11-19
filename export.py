"""Encrypted PDF/CSV export helpers for the LAN Traffic Analyzer."""

import base64
import csv
import io
import os
import secrets

import database

CSV_MAGIC = b"LANTRAFFICCSV1"
PBKDF2_ITERATIONS = 600_000


def _derive_fernet(password, salt):
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as error:
        raise RuntimeError(
            "The cryptography package is required. "
            "Install it with: python -m pip install cryptography"
        ) from error

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def _csv_bytes(packets):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "Packet ID", "Timestamp", "Source IP", "Destination IP",
        "Protocol", "Length", "Source Port", "Destination Port", "Info",
    ])
    writer.writerows(packets)
    return output.getvalue().encode("utf-8-sig")


def export_csv(file_path, password, packets=None):
    if not password:
        raise ValueError("A password is required for CSV export.")

    packets = database.get_export_packets() if packets is None else packets
    salt = secrets.token_bytes(16)
    encrypted = _derive_fernet(password, salt).encrypt(_csv_bytes(packets))

    with open(file_path, "wb") as output:
        output.write(CSV_MAGIC + salt + encrypted)


def decrypt_csv_file(encrypted_file_path, output_csv_path, password):
    if not password:
        raise ValueError("A password is required to decrypt the CSV.")

    with open(encrypted_file_path, "rb") as input_file:
        payload = input_file.read()

    header_length = len(CSV_MAGIC)
    if not payload.startswith(CSV_MAGIC) or len(payload) <= header_length + 16:
        raise ValueError("This is not a supported encrypted LAN Traffic Analyzer CSV.")

    salt = payload[header_length:header_length + 16]
    token = payload[header_length + 16:]
    try:
        plaintext = _derive_fernet(password, salt).decrypt(token)
    except Exception as error:
        raise ValueError("Incorrect password or the encrypted CSV file is damaged.") from error

    with open(output_csv_path, "wb") as output:
        output.write(plaintext)


def export_pdf(file_path, password, packets):
    if not password:
        raise ValueError("A password is required for PDF export.")

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from pypdf import PdfReader, PdfWriter
        from xml.sax.saxutils import escape
    except ImportError as error:
        raise RuntimeError(
            "Install required packages using: python -m pip install reportlab pypdf"
        ) from error

    headers = [
        "Packet ID", "Timestamp", "Source IP", "Destination IP",
        "Protocol", "Length", "Source Port", "Destination Port", "Info",
    ]
    temp_file = file_path + ".temp.pdf"
    try:
        document = SimpleDocTemplate(
            temp_file,
            pagesize=landscape(A4),
            rightMargin=10 * mm,
            leftMargin=10 * mm,
            topMargin=12 * mm,
            bottomMargin=12 * mm,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontSize=16,
            spaceAfter=4,
        )
        cell_style = ParagraphStyle(
            "PacketCell",
            parent=styles["BodyText"],
            fontSize=6.5,
            leading=8,
            wordWrap="CJK",
        )
        story = [
            Paragraph("LAN Traffic Analyzer - Packet Export", title_style),
            Paragraph(
                f"Generated: packet report | Total packets: {len(packets):,}",
                styles["Normal"],
            ),
            Spacer(1, 8),
        ]
        table_data = [
            [Paragraph(escape(str(value)), cell_style) for value in headers]
        ]
        for packet in packets:
            table_data.append([
                Paragraph(escape("" if value is None else str(value)), cell_style)
                for value in packet
            ])
        table = Table(
            table_data,
            repeatRows=1,
            colWidths=[
                13 * mm, 29 * mm, 27 * mm, 27 * mm, 17 * mm,
                13 * mm, 17 * mm, 19 * mm, 90 * mm,
            ],
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243447")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f1f5f9")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(table)
        document.build(story)

        reader = PdfReader(temp_file)
        writer = PdfWriter()
        writer.append_pages_from_reader(reader)
        writer.encrypt(
            user_password=password,
            owner_password=password + secrets.token_hex(8),
            algorithm="AES-256",
        )
        with open(file_path, "wb") as output:
            writer.write(output)

        verification = PdfReader(file_path)
        if not verification.is_encrypted:
            raise RuntimeError("PDF password encryption failed. The exported PDF is not encrypted.")
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
