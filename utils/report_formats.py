from fpdf import FPDF; from pathlib import Path; from xhtml2pdf import pisa; import csv, io, yaml, json, os

def gen_markdown(vulnerabilities):
    lines = ["# Vulnfy Security Report\n", "| CVE / ID | Severity | Description |", "|---|---|---|"]
    for v in vulnerabilities:
        v_id = v.get("cve") or v.get("vulnerability_id") or v.get("id") or "N/A"
        desc = v.get("description", "N/A").replace("\n", " ")
        lines.append(f"| {v_id} | {v.get('severity', 'UNKNOWN')} | {desc} |")
    return "\n".join(lines)

def gen_html(vulnerabilities):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(current_dir, "templates")    
    rows_html = ""
    for v in vulnerabilities:
        v_id = v.get("cve") or v.get("vulnerability_id") or v.get("id") or "N/A"
        severity = v.get("severity", "UNKNOWN").upper()
        package = v.get("package", "N/A")
        description = v.get("description", "No description provided.")
        
        rows_html += f"""
            <tr>
                <td><strong>{v_id}</strong></td>
                <td><span class="badge {severity.lower()}">{severity}</span></td>
                <td>{package}</td>
                <td>{description}</td>
            </tr>
        """
    
    if not rows_html:
        rows_html = '<tr><td colspan="4" style="text-align: center;">No vulnerabilities has been found 🎉</td></tr>'

    with open(os.path.join(templates_dir, "index.html"), "r", encoding="utf-8") as f:
        html_template = f.read()
        
    try:
        with open(os.path.join(templates_dir, "style.css"), "r", encoding="utf-8") as f:
            css_content = f.read()
    except FileNotFoundError:
        css_content = "/* CSS nebyl nalezen */"

    final_html = html_template.replace("__CSS_PLACEHOLDER__", css_content)
    final_html = final_html.replace("__ROWS_PLACEHOLDER__", rows_html)
    
    return final_html
    
def gen_pdf(vulnerabilities, out_path="security_report.pdf"):
    html_content = gen_html(vulnerabilities)
    with open(out_path, "wb") as pdf_f:
        pisa_stats = pisa.CreatePDF(html_content, dest=pdf_f)
    return not pisa_stats.err

def gen_csv(vulnerabilities):
    out = io.StringIO()
    fieldnames = ["id", "severity", "package", "description"]
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    for v in vulnerabilities:
        row = {
            "id": v.get("vulnerability_id", v.get("id", "N/A")),
            "severity": v.get("severity", "UNKNOWN"),
            "package": v.get("package", "N/A"),
            "description": v.get("description", "No description")
        }
        writer.writerow(row)
    return out.getvalue()

def gen_yaml(vulnerabilities):
    return yaml.safe_dump(vulnerabilities, sort_keys=False, allow_unicode=True)

def gen_json(vulnerabilities):
    return json.dumps(vulnerabilities, indent=4, ensure_ascii=False)