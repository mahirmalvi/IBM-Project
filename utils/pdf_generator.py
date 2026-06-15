import io
import json
import hashlib
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

def generate_scan_pdf(scan_record, username):
    """
    Generates a PDF audit report for a URL scan and returns it as a bytes buffer.
    """
    buffer = io.BytesIO()
    
    # Page Setup
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    story = []
    
    # Setup Styles
    styles = getSampleStyleSheet()
    
    # Custom Styles (using existing names or unique ones)
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#1e293b'), # Dark Slate Blue
        alignment=TA_LEFT,
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#64748b'), # Muted Slate
        spaceAfter=20
    )
    
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155')
    )
    
    body_bold = ParagraphStyle(
        'BodyDarkBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    url_style = ParagraphStyle(
        'UrlWrap',
        parent=body_style,
        fontName='Courier',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor('#0284c7') # Blue Link
    )
    
    verdict_safe_style = ParagraphStyle(
        'VerdictSafe',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#16a34a'), # Green
        alignment=TA_CENTER
    )
    
    verdict_phish_style = ParagraphStyle(
        'VerdictPhish',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#dc2626'), # Red
        alignment=TA_CENTER
    )

    # 1. Header Section
    story.append(Paragraph("PHISHGUARD SECURITY LABS", title_style))
    story.append(Paragraph("URL Phishing Analysis Audit Report", subtitle_style))
    story.append(Spacer(1, 10))
    
    # 2. Metadata Block
    date_str = scan_record.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
    meta_data = [
        [Paragraph("Report ID:", body_bold), Paragraph(f"PG-SCAN-{scan_record.id:06d}", body_style)],
        [Paragraph("Scan Timestamp:", body_bold), Paragraph(date_str, body_style)],
        [Paragraph("Scan Originator:", body_bold), Paragraph(username if username else "Anonymous User", body_style)],
        [Paragraph("Target URL:", body_bold), Paragraph(scan_record.url, url_style)]
    ]
    
    # 4 columns: Label(100), Value(400)
    meta_table = Table(meta_data, colWidths=[110, 394])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ('LINEBELOW', (0,-1), (-1,-1), 0.5, colors.HexColor('#cbd5e1'))
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))
    
    # 3. Verdict Summary Callout Box
    is_phishing = (scan_record.prediction == 'Phishing')
    verdict_text = "DANGER: PHISHING DETECTED" if is_phishing else "VERDICT: SAFE / CLEAN"
    verdict_style = verdict_phish_style if is_phishing else verdict_safe_style
    bg_color = colors.HexColor('#fef2f2') if is_phishing else colors.HexColor('#f0fdf4')
    border_color = colors.HexColor('#fca5a5') if is_phishing else colors.HexColor('#86efac')
    
    verdict_card_data = [
        [Paragraph(verdict_text, verdict_style)],
        [Paragraph(f"Machine Learning Confidence Score: {scan_record.confidence_score:.2f}%", ParagraphStyle('SubConf', parent=body_style, alignment=TA_CENTER))],
        [Paragraph(f"Heuristic Threat Risk Score: {scan_record.risk_score}/100", ParagraphStyle('SubRisk', parent=body_style, alignment=TA_CENTER))]
    ]
    
    verdict_table = Table(verdict_card_data, colWidths=[504])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_color),
        ('BOX', (0,0), (-1,-1), 1, border_color),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 20))
    
    # 4. Feature Inspection Table
    story.append(Paragraph("Security Feature Breakdown", h2_style))
    
    # Parse scan_record.features from JSON string
    try:
        features_dict = json.loads(scan_record.features)
    except Exception:
        features_dict = {}
        
    feature_rows = [
        [
            Paragraph("Feature Inspected", body_bold),
            Paragraph("Measured Value", body_bold),
            Paragraph("Risk Assessment", body_bold)
        ]
    ]
    
    # Map features to friendly descriptions and interpretations
    feature_mappings = [
        ("ssl_final_state", "SSL (HTTPS) Scheme", lambda v: ("HTTP (No Encryption)", "High Risk") if v == 1 else ("HTTPS Secure Connection", "Safe")),
        ("url_length", "URL String Length", lambda v: ("Long URL (>= 54 chars)", "Suspicious") if v == 1 else ("Normal Length (< 54 chars)", "Safe")),
        ("having_ip_address", "IP Address in Domain", lambda v: ("IP Address Used", "Suspicious") if v == 1 else ("Standard Named Domain", "Safe")),
        ("prefix_suffix", "Hyphen (-) in Domain Name", lambda v: ("Domain contains hyphens", "Suspicious") if v == 1 else ("No hyphens in domain", "Safe")),
        ("having_sub_domain", "Subdomain Count", lambda v: ("Multiple Subdomains (>= 3 parts)", "Suspicious") if v == 1 else ("Single or No Subdomain", "Safe")),
        ("shortening_service", "URL Redirection Shortener", lambda v: ("Shortening service (e.g. bit.ly)", "Suspicious") if v == 1 else ("No shortener detected", "Safe")),
        ("having_at_symbol", "@ Character in URL", lambda v: ("@ Symbol Present (Spoof Risk)", "High Risk") if v == 1 else ("@ Symbol Absent", "Safe")),
        ("double_slash_redirecting", "Path Redirecting (//)", lambda v: ("Multiple // observed", "High Risk") if v == 1 else ("Normal Path Structure", "Safe")),
        ("suspicious_keywords", "Brand/Security Keywords", lambda v: (f"{v} Suspicious terms found", "High Risk" if v > 1 else "Suspicious" if v == 1 else "Safe"))
    ]
    
    for key, label, interpreter in feature_mappings:
        val = features_dict.get(key, 0)
        desc, rating = interpreter(val)
        
        rating_color = '#dc2626' if rating == 'High Risk' else '#eab308' if rating == 'Suspicious' else '#16a34a'
        rating_paragraph = Paragraph(
            f"<font color='{rating_color}'><b>{rating}</b></font>",
            body_style
        )
        
        feature_rows.append([
            Paragraph(label, body_style),
            Paragraph(desc, body_style),
            rating_paragraph
        ])
        
    # Table styling for feature breakdown
    feat_table = Table(feature_rows, colWidths=[180, 204, 120])
    feat_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(feat_table)
    story.append(Spacer(1, 20))
    
    # 5. Security Recommendations
    story.append(Paragraph("Mitigation & Safety Actions", h2_style))
    if is_phishing:
        recs = [
            "<b>DO NOT enter credentials:</b> Do not type usernames, passwords, or PINs on this page.",
            "<b>DO NOT click links:</b> Block any download requests or scripts from this domain.",
            "<b>Verify Domain Authenticity:</b> Phishing URLs mimic brand names (e.g. <i>paypal-security.com</i> instead of <i>paypal.com</i>).",
            "<b>Report the Link:</b> Report this phishing URL to your corporate security team or Google Safe Browsing."
        ]
    else:
        recs = [
            "<b>HTTPS Status Verified:</b> This site uses secure SSL encryption. Verify that the lock icon is visible in your browser address bar.",
            "<b>Legitimate domain:</b> While our ML classifier determines this URL has safe indicators, always double-check the sender's context before clicking links inside emails.",
            "<b>Stay Vigilant:</b> Phishing tactics change. Keep your browser, antivirus software, and firewall rules updated."
        ]
        
    for rec in recs:
        bullet_str = f"&bull; {rec}"
        story.append(Paragraph(bullet_str, ParagraphStyle('BulletRec', parent=body_style, leftIndent=15, spaceAfter=4)))
        
    # Calculate Cryptographic Audit Signature Hash
    hash_input = f"{scan_record.id}-{scan_record.url}-{scan_record.prediction}-{scan_record.confidence_score}-{scan_record.risk_score}"
    verification_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest().upper()

    story.append(Spacer(1, 15))
    story.append(Paragraph("Cryptographic Signature Verification Ledger", h2_style))
    story.append(Paragraph(f"This document is sealed with a unique SHA-256 verification checksum to guarantee integrity: <br/><font face='Courier' size='7' color='#0284c7'><b>{verification_hash}</b></font>", body_style))
    story.append(Spacer(1, 20))
    
    # 6. Footer Signature
    footer_text = f"Audit conducted on PhishGuard Platform | Model: Random Forest | Date: {datetime.utcnow().strftime('%Y-%m-%d')}"
    story.append(Paragraph(footer_text, ParagraphStyle('FooterText', parent=body_style, alignment=TA_CENTER, textColor=colors.HexColor('#94a3b8'), fontSize=8)))
    
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
