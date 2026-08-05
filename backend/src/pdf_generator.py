import os
import json
from fpdf import FPDF
from datetime import datetime

class ReportPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'Vulnerability Report', ln=True, align='C')
        self.ln(10)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_vulnerability_pdf(project_id: str, report_json_path: str, output_pdf_path: str):
    """
    Reads a Semgrep JSON report and generates a formatted PDF.
    """
    if not os.path.exists(report_json_path):
        raise FileNotFoundError(f"Report JSON not found at {report_json_path}")
        
    with open(report_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    results = data.get("results", [])
    
    # Calculate counts
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in results:
        sev = finding.get("extra", {}).get("severity", "").lower()
        if sev in ("error", "high"):
            counts["high"] += 1
        elif sev in ("warning", "medium"):
            counts["medium"] += 1
        else:
            counts["low"] += 1
            
    pdf = ReportPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Meta information
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 10, f"Project ID: {project_id}", ln=True)
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.cell(0, 10, f"Total Findings: {len(results)}", ln=True)
    pdf.cell(0, 10, f"High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']}", ln=True)
    
    pdf.ln(10)
    
    if not results:
        pdf.set_font("Helvetica", "I", 12)
        pdf.cell(0, 10, "No vulnerabilities found.", ln=True)
    else:
        from src.chain import generate_vulnerability_report
        for idx, finding in enumerate(results, 1):
            pdf.add_page()
            
            sev = finding.get("extra", {}).get("severity", "UNKNOWN")
            path = finding.get("path", "Unknown file")
            line = finding.get("start", {}).get("line", "Unknown line")
            message = finding.get("extra", {}).get("message", "").replace('\n', ' ')
            lines = finding.get("extra", {}).get("lines", "")
            
            # Title
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 8, f"Finding {idx}: [{sev.upper()}] in {path}:{line}", ln=True)
            
            # Message
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(0, 6, f"Message: {message}")
            
            # Code snippet
            if lines:
                pdf.ln(2)
                pdf.set_font("Courier", "", 9)
                # handle unicode errors in PDF rendering
                safe_lines = lines.encode('latin-1', 'replace').decode('latin-1')
                pdf.multi_cell(0, 5, safe_lines, border=1)
                
            pdf.ln(8)
            
            # AI Triage
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 8, "AI Generated Detailed Report:", ln=True)
            pdf.ln(2)
            
            try:
                ai_report = generate_vulnerability_report(project_id, finding)
            except Exception as e:
                ai_report = f"Failed to generate AI report: {e}"
                
            pdf.set_font("Helvetica", "", 10)
            safe_ai = ai_report.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, safe_ai)
            
    pdf.output(output_pdf_path)
