"""
Format compliance text in DB — converts raw concatenated text into markdown.
Run via: kubectl exec deploy/engine-compliance -- python3 /app/scripts/format_compliance_text.py
Or locally: python3 scripts/format_compliance_text.py
"""
import os
import re
import psycopg2

def format_compliance_text(raw):
    """Format raw compliance text into clean markdown."""
    if not raw or not raw.strip():
        return raw
    text = raw.strip()

    # 1. Split numbered steps: "1. Title Text... 2. Title Text..."
    parts = re.split(r'(?<=[.!?:)])\s+(?=\d+\.\s+[A-Z])', text)

    if len(parts) > 1:
        lines = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            m = re.match(r'^(\d+)\.\s+(.+)', part, re.DOTALL)
            if m:
                num = m.group(1)
                rest = m.group(2)
                # Bold the title — first phrase up to a natural break
                title_end = re.search(r'(?<=[a-z):])\s+(?=[A-Z][a-z])', rest)
                if title_end and title_end.start() < 80:
                    title = rest[:title_end.start()].strip()
                    body = rest[title_end.start():].strip()
                    lines.append(f"{num}. **{title}**\n   {body}")
                else:
                    lines.append(f"{num}. {rest}")
            else:
                lines.append(part)
        return "\n\n".join(lines)

    # 2. References pattern
    if text.startswith("References:"):
        refs = re.findall(r'(https?://\S+)', text)
        if refs:
            lines = ["**References:**\n"]
            for url in refs:
                lines.append(f"- {url}")
            return "\n".join(lines)

    # 3. Long paragraph — break into paragraphs at sentence boundaries
    if len(text) > 300 and text.count('. ') > 3:
        sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z])', text)
        if len(sentences) > 2:
            return "\n\n".join(s.strip() for s in sentences if s.strip())

    return text


def main():
    conn = psycopg2.connect(
        host=os.environ.get('COMPLIANCE_DB_HOST', 'localhost'),
        port=int(os.environ.get('COMPLIANCE_DB_PORT', '5432')),
        database=os.environ.get('COMPLIANCE_DB_NAME', 'threat_engine_compliance'),
        user=os.environ.get('COMPLIANCE_DB_USER', 'postgres'),
        password=os.environ.get('COMPLIANCE_DB_PASSWORD', ''),
    )
    cur = conn.cursor()

    # Process testing_procedures
    cur.execute("SELECT control_id, testing_procedures FROM compliance_controls WHERE testing_procedures IS NOT NULL AND testing_procedures != ''")
    rows = cur.fetchall()
    updated_testing = 0
    for cid, raw in rows:
        formatted = format_compliance_text(raw)
        if formatted != raw:
            cur.execute("UPDATE compliance_controls SET testing_procedures = %s WHERE control_id = %s", (formatted, cid))
            updated_testing += 1

    # Process implementation_guidance
    cur.execute("SELECT control_id, implementation_guidance FROM compliance_controls WHERE implementation_guidance IS NOT NULL AND implementation_guidance != ''")
    rows = cur.fetchall()
    updated_guidance = 0
    for cid, raw in rows:
        formatted = format_compliance_text(raw)
        if formatted != raw:
            cur.execute("UPDATE compliance_controls SET implementation_guidance = %s WHERE control_id = %s", (formatted, cid))
            updated_guidance += 1

    # Process control_description
    cur.execute("SELECT control_id, control_description FROM compliance_controls WHERE control_description IS NOT NULL AND LENGTH(control_description) > 300")
    rows = cur.fetchall()
    updated_desc = 0
    for cid, raw in rows:
        formatted = format_compliance_text(raw)
        if formatted != raw:
            cur.execute("UPDATE compliance_controls SET control_description = %s WHERE control_id = %s", (formatted, cid))
            updated_desc += 1

    conn.commit()
    print(f"Updated testing_procedures: {updated_testing}")
    print(f"Updated implementation_guidance: {updated_guidance}")
    print(f"Updated control_description: {updated_desc}")
    conn.close()


if __name__ == '__main__':
    main()
