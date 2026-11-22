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


def _csv_bytes(packets, report=None):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    if report:
        header = report["header"]
        writer.writerow([header.get("title", "LAN Traffic Analyzer - Network Report")])
        writer.writerow(["Capture", header.get("capture", "")])
        writer.writerow(["Generated", header.get("generated", "")])
        writer.writerow(["First packet", header.get("first_packet", "")])
        writer.writerow(["Last packet", header.get("last_packet", "")])
        writer.writerow(["Packets", header.get("packet_count", 0)])
        writer.writerow(["Total bytes", header.get("total_bytes", 0)])
        writer.writerow(["LAN clients", header.get("client_count", 0)])
        writer.writerow(["Dropped packets", header.get("dropped_packets", "")])
        writer.writerow(["Packet table scope", header.get("packet_scope", "")])

        writer.writerow([])
        writer.writerow(["Gateway health"])
        health = report.get("health", {})
        writer.writerow(["State", health.get("state", "")])
        writer.writerow(["Details", health.get("description", "")])
        writer.writerow(["Checked at", health.get("checked_at", "")])
        writer.writerow(["Context", health.get("context", "")])

        writer.writerow([])
        writer.writerow(["Protocol summary"])
        writer.writerow(["Protocol", "Packets", "Share (%)"])
        for item in report.get("protocols", []):
            writer.writerow([
                item.get("protocol", ""),
                item.get("packets", 0),
                f'{item.get("percentage", 0):.1f}',
            ])

        writer.writerow([])
        writer.writerow(["Advice"])
        writer.writerow(["Priority", "Observation", "Details", "Recommended action"])
        for item in report.get("advice", []):
            writer.writerow([
                item.get("level", ""),
                item.get("title", ""),
                item.get("detail", ""),
                item.get("action", ""),
            ])

        writer.writerow([])
        writer.writerow(["LAN client list"])
        writer.writerow([
            "IP address", "MAC address", "Sent packets", "Received packets",
            "Sent bytes", "Received bytes", "Total bytes", "Protocols",
        ])
        for client in report.get("clients", []):
            writer.writerow([
                client.get("ip", ""),
                client.get("mac", "") or "Not recorded",
                client.get("sent_packets", 0),
                client.get("received_packets", 0),
                client.get("sent_bytes", 0),
                client.get("received_bytes", 0),
                client.get("total_bytes", 0),
                ", ".join(client.get("protocols", [])),
            ])

        writer.writerow([])
        writer.writerow(["Network tree"])
        writer.writerow(["Network", "Client IP", "MAC address", "Total bytes"])
        for network in report.get("tree", []):
            for client in network.get("clients", []):
                writer.writerow([
                    network.get("network", ""),
                    client.get("ip", ""),
                    client.get("mac", "") or "Not recorded",
                    client.get("total_bytes", 0),
                ])
        writer.writerow([])
        writer.writerow(["Packet records"])

    writer.writerow([
        "Packet ID", "Timestamp", "Source IP", "Destination IP",
        "Protocol", "Length", "Source Port", "Destination Port", "Info",
    ])
    writer.writerows(packets)
    return output.getvalue().encode("utf-8-sig")


def export_csv(file_path, password, packets=None, report=None):
    if not password:
        raise ValueError("A password is required for CSV export.")

    packets = database.get_export_packets() if packets is None else packets
    salt = secrets.token_bytes(16)
    encrypted = _derive_fernet(password, salt).encrypt(_csv_bytes(packets, report))

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


def export_pdf(file_path, password, packets, report=None):
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
            Paragraph(
                escape(
                    report.get("header", {}).get(
                        "title", "LAN Traffic Analyzer - Packet Export"
                    ) if report else "LAN Traffic Analyzer - Packet Export"
                ),
                title_style,
            ),
        ]
        if report:
            header = report.get("header", {})
            summary_rows = [
                ["Capture", str(header.get("capture", ""))],
                ["Generated", str(header.get("generated", ""))],
                ["Packet times", f'{header.get("first_packet", "—")} to {header.get("last_packet", "—")}'],
                ["Packets / bytes", f'{header.get("packet_count", 0):,} / {header.get("total_bytes", 0):,}'],
                ["LAN clients / dropped", f'{header.get("client_count", 0):,} / {header.get("dropped_packets", "")}'],
                ["Packet table", str(header.get("packet_scope", ""))],
            ]
            summary_table = Table(summary_rows, colWidths=[42 * mm, 225 * mm])
            summary_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.extend([
                Paragraph("Capture overview", styles["Heading2"]),
                summary_table,
            ])

            health = report.get("health", {})
            story.extend([
                Spacer(1, 6),
                Paragraph("Gateway health", styles["Heading2"]),
                Paragraph(
                    escape(
                        f'{health.get("state", "unavailable").replace("_", " ").title()}: '
                        f'{health.get("description", "")}'
                    ),
                    styles["Normal"],
                ),
                Paragraph(
                    escape(
                        f'{health.get("context", "")} '
                        f'Checked: {health.get("checked_at") or "Not recorded"}.'
                    ),
                    cell_style,
                ),
            ])

            def append_report_table(title, headers, rows, widths):
                story.append(Spacer(1, 6))
                story.append(Paragraph(escape(title), styles["Heading2"]))
                data = [[
                    Paragraph(escape(str(value)), cell_style) for value in headers
                ]]
                data.extend([
                    [
                        Paragraph(escape("" if value is None else str(value)), cell_style)
                        for value in row
                    ]
                    for row in rows
                ])
                section_table = Table(data, repeatRows=1, colWidths=widths)
                section_table.setStyle(TableStyle([
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
                story.append(section_table)

            append_report_table(
                "Protocol summary",
                ["Protocol", "Packets", "Share"],
                [
                    [item.get("protocol", ""), item.get("packets", 0),
                     f'{item.get("percentage", 0):.1f}%']
                    for item in report.get("protocols", [])
                ] or [["No protocol data", 0, "0%"]],
                [80 * mm, 40 * mm, 40 * mm],
            )
            append_report_table(
                "Advice",
                ["Priority", "Observation", "Details", "Recommended action"],
                [
                    [
                        item.get("level", ""),
                        item.get("title", ""),
                        item.get("detail", ""),
                        item.get("action", ""),
                    ]
                    for item in report.get("advice", [])
                ] or [["info", "No advice", "No advice is available.", ""]],
                [25 * mm, 48 * mm, 90 * mm, 92 * mm],
            )
            append_report_table(
                "LAN client list",
                ["IP address", "MAC address", "Sent", "Received", "Sent bytes", "Received bytes", "Total bytes"],
                [
                    [
                        item.get("ip", ""),
                        item.get("mac", "") or "Not recorded",
                        item.get("sent_packets", 0),
                        item.get("received_packets", 0),
                        item.get("sent_bytes", 0),
                        item.get("received_bytes", 0),
                        item.get("total_bytes", 0),
                    ]
                    for item in report.get("clients", [])
                ] or [["No LAN clients observed", "", "", "", "", "", ""]],
                [35 * mm, 35 * mm, 23 * mm, 23 * mm, 38 * mm, 38 * mm, 38 * mm],
            )
            append_report_table(
                "Network tree",
                ["Network", "Client IP", "MAC address", "Total bytes"],
                [
                    [
                        network.get("network", ""),
                        client.get("ip", ""),
                        client.get("mac", "") or "Not recorded",
                        client.get("total_bytes", 0),
                    ]
                    for network in report.get("tree", [])
                    for client in network.get("clients", [])
                ] or [["No LAN tree data", "", "", ""]],
                [65 * mm, 55 * mm, 65 * mm, 50 * mm],
            )
            story.append(Spacer(1, 8))
            story.append(Paragraph("Packet records", styles["Heading2"]))
        else:
            story.append(Paragraph(
                f"Generated: packet report | Total packets: {len(packets):,}",
                styles["Normal"],
            ))
        story.append(Spacer(1, 8))
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
