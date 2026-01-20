"""
PDF Exporter

Exports compliance reports as PDF (audit-ready).
"""

from typing import Dict, Any, Optional
from io import BytesIO
from datetime import datetime

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class PDFExporter:
    """Exports compliance reports as PDF."""
    
    @staticmethod
    def export_executive_summary(report: Dict[str, Any], output_path: Optional[str] = None) -> bytes:
        """
        Export executive dashboard as PDF.
        
        Args:
            report: Executive dashboard dictionary
            output_path: Optional file path to save PDF
        
        Returns:
            PDF bytes
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF export. Install with: pip install reportlab")
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=1  # Center
        )
        story.append(Paragraph("Compliance Report - Executive Summary", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Report metadata
        meta_style = styles['Normal']
        scan_id = report.get('scan_id', 'N/A')
        csp = report.get('csp', 'N/A')
        scanned_at = report.get('scanned_at', 'N/A')
        generated_at = report.get('generated_at', datetime.utcnow().isoformat())
        
        story.append(Paragraph(f"<b>Scan ID:</b> {scan_id}", meta_style))
        story.append(Paragraph(f"<b>Cloud Provider:</b> {csp.upper()}", meta_style))
        story.append(Paragraph(f"<b>Scanned At:</b> {scanned_at}", meta_style))
        story.append(Paragraph(f"<b>Report Generated:</b> {generated_at}", meta_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Summary section
        summary = report.get('summary', {})
        overall_score = summary.get('overall_compliance_score', 0.0)
        
        story.append(Paragraph("<b>Overall Compliance Score</b>", styles['Heading2']))
        score_style = ParagraphStyle(
            'Score',
            parent=styles['Heading1'],
            fontSize=48,
            textColor=colors.HexColor('#2e7d32') if overall_score >= 80 else colors.HexColor('#d32f2f'),
            alignment=1
        )
        story.append(Paragraph(f"{overall_score:.1f}%", score_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Framework summary table
        story.append(Paragraph("<b>Framework Compliance Summary</b>", styles['Heading2']))
        frameworks = report.get('frameworks', [])
        
        if frameworks:
            data = [['Framework', 'Score', 'Status', 'Controls']]
            for fw in frameworks:
                data.append([
                    fw.get('framework', 'N/A'),
                    f"{fw.get('compliance_score', 0):.1f}%",
                    fw.get('status', 'N/A'),
                    f"{fw.get('controls_passed', 0)}/{fw.get('controls_total', 0)}"
                ])
            
            table = Table(data, colWidths=[3*inch, 1*inch, 1.5*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            story.append(table)
            story.append(Spacer(1, 0.3*inch))
        
        # Findings summary
        story.append(Paragraph("<b>Findings Summary</b>", styles['Heading2']))
        findings_data = [
            ['Severity', 'Count'],
            ['Critical', str(summary.get('critical_findings', 0))],
            ['High', str(summary.get('high_findings', 0))],
            ['Medium', str(summary.get('medium_findings', 0))],
            ['Low', str(summary.get('low_findings', 0))]
        ]
        
        findings_table = Table(findings_data, colWidths=[2*inch, 1*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(findings_table)
        
        # Build PDF
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
        
        return pdf_bytes
    
    @staticmethod
    def export_framework_report(report: Dict[str, Any], output_path: Optional[str] = None) -> bytes:
        """
        Export framework report as PDF.
        
        Args:
            report: Framework report dictionary
            output_path: Optional file path to save PDF
        
        Returns:
            PDF bytes
        """
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF export. Install with: pip install reportlab")
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        framework = report.get('framework', 'N/A')
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=20,
            alignment=1
        )
        story.append(Paragraph(f"Compliance Report - {framework}", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Framework summary
        score = report.get('compliance_score', 0.0)
        status = report.get('overall_status', 'N/A')
        stats = report.get('statistics', {})
        
        story.append(Paragraph(f"<b>Compliance Score:</b> {score:.1f}%", styles['Normal']))
        story.append(Paragraph(f"<b>Status:</b> {status}", styles['Normal']))
        story.append(Paragraph(f"<b>Controls Total:</b> {stats.get('controls_total', 0)}", styles['Normal']))
        story.append(Paragraph(f"<b>Controls Passed:</b> {stats.get('controls_passed', 0)}", styles['Normal']))
        story.append(Paragraph(f"<b>Controls Failed:</b> {stats.get('controls_failed', 0)}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Controls table
        story.append(Paragraph("<b>Control Details</b>", styles['Heading2']))
        controls = report.get('controls', [])
        
        if controls:
            data = [['Control ID', 'Title', 'Status', 'Checks']]
            for control in controls[:50]:  # Limit to first 50 controls
                data.append([
                    control.get('control_id', 'N/A'),
                    control.get('control_title', 'N/A')[:50] + '...' if len(control.get('control_title', '')) > 50 else control.get('control_title', 'N/A'),
                    control.get('status', 'N/A'),
                    f"{control.get('checks_passed', 0)}/{control.get('checks_total', 0)}"
                ])
            
            table = Table(data, colWidths=[1.5*inch, 3*inch, 1*inch, 1*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            story.append(table)
        
        # Build PDF
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
        
        return pdf_bytes

