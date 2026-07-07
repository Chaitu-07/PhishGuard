from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch


def create_pdf_report(
    filename,
    url,
    score,
    verdict,
    threat_level,
    reasons,
    recommendations,
    whois_data,
    ssl_data,
    dns_data,
    scan_time
):

    styles = getSampleStyleSheet()

    title_style = styles["Heading1"]
    title_style.alignment = TA_CENTER

    heading = styles["Heading2"]

    normal = styles["BodyText"]

    doc = SimpleDocTemplate(filename)

    story = []

    # =====================================
    # Title
    # =====================================

    story.append(

        Paragraph(

            "PHISHGUARD SECURITY REPORT",

            title_style

        )

    )

    story.append(Spacer(1, 0.30 * inch))

    # =====================================
    # Summary
    # =====================================

    summary = [

        ["Website", url],

        ["Risk Score", f"{score}%"],

        ["Verdict", verdict],

        ["Threat Level", threat_level],

        ["Scan Time", scan_time]

    ]

    table = Table(summary)

    table.setStyle(

        TableStyle([

            ("GRID",(0,0),(-1,-1),1,colors.grey),

            ("BACKGROUND",(0,0),(0,-1),colors.lightgrey),

            ("BACKGROUND",(1,0),(1,-1),colors.whitesmoke),

            ("FONTNAME",(0,0),(-1,-1),"Helvetica"),

            ("BOTTOMPADDING",(0,0),(-1,-1),8)

        ])

    )

    story.append(table)

    story.append(Spacer(1,0.30*inch))

    # =====================================
    # WHOIS
    # =====================================

    story.append(Paragraph("WHOIS Information", heading))

    story.append(Spacer(1,0.15*inch))

    whois_table = Table([

        ["Domain", whois_data["domain"]],

        ["Registrar", whois_data["registrar"]],

        ["Country", whois_data["country"]],

        ["Created", whois_data["creation_date"]],

        ["Expires", whois_data["expiration_date"]],

        ["Domain Age", whois_data["domain_age"]]

    ])

    whois_table.setStyle(

        TableStyle([

            ("GRID",(0,0),(-1,-1),1,colors.grey),

            ("BACKGROUND",(0,0),(0,-1),colors.beige)

        ])

    )

    story.append(whois_table)

    story.append(Spacer(1,0.30*inch))

    # =====================================
    # SSL
    # =====================================

    story.append(Paragraph("SSL Certificate", heading))

    story.append(Spacer(1,0.15*inch))

    ssl_table = Table([

        ["Status", ssl_data["status"]],

        ["Issuer", ssl_data["issuer"]],

        ["Common Name", ssl_data["common_name"]],

        ["TLS Version", ssl_data["tls_version"]],

        ["Valid From", ssl_data["valid_from"]],

        ["Valid Until", ssl_data["valid_until"]]

    ])

    ssl_table.setStyle(

        TableStyle([

            ("GRID",(0,0),(-1,-1),1,colors.grey),

            ("BACKGROUND",(0,0),(0,-1),colors.beige)

        ])

    )

    story.append(ssl_table)

    story.append(Spacer(1,0.30*inch))

    # =====================================
    # DNS
    # =====================================

    story.append(Paragraph("Website Information", heading))

    story.append(Spacer(1,0.15*inch))

    dns_table = Table([

        ["Hostname", dns_data["hostname"]],

        ["IPv4", dns_data["ip"]],

        ["Protocol", dns_data["protocol"]],

        ["Port", str(dns_data["port"])],

        ["TLD", dns_data["tld"]]

    ])

    dns_table.setStyle(

        TableStyle([

            ("GRID",(0,0),(-1,-1),1,colors.grey),

            ("BACKGROUND",(0,0),(0,-1),colors.beige)

        ])

    )

    story.append(dns_table)

    story.append(Spacer(1,0.30*inch))

    # =====================================
    # Threat Indicators
    # =====================================

    story.append(Paragraph("Threat Indicators", heading))

    story.append(Spacer(1,0.15*inch))

    for reason in reasons:

        story.append(

            Paragraph(

                f"• {reason}",

                normal

            )

        )

    story.append(Spacer(1,0.30*inch))

    # =====================================
    # Recommendations
    # =====================================

    story.append(

        Paragraph(

            "Recommendations",

            heading

        )

    )

    story.append(Spacer(1,0.15*inch))

    for item in recommendations:

        story.append(

            Paragraph(

                f"• {item}",

                normal

            )

        )

    story.append(Spacer(1,0.40*inch))

    story.append(

        Paragraph(

            "<b>Generated by PhishGuard</b>",

            normal

        )

    )

    doc.build(story)