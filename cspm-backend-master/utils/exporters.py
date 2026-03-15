# your_app/utils/exporters.py
import openpyxl
from io import BytesIO
from django.template.loader import get_template

def generate_label(field):
    return field.replace("_", " ").title()

def export_to_excel(data, labels=None):
    if labels is None:
        labels = {}
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Tenants"

    if not data:
        ws.append(["No data available"])
        buffer = BytesIO()
        wb.save(buffer)
        return buffer.getvalue()

    fields = list(data[0].keys())
    headers = [labels.get(f, generate_label(f)) for f in fields]
    ws.append(headers)

    for row in data:
        ws.append([str(row.get(f, "")) for f in fields])

    for col in ws.columns:
        max_length = 0
        column = col[0].column_letter
        for cell in col:
            if cell.value:
                max_length = max(max_length, len(str(cell.value)))
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column].width = adjusted_width

    buffer = BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def export_to_pdf(data, labels=None):
    if labels is None:
        labels = {}

    context = {
        "headers": [labels.get(k, generate_label(k)) for k in (data[0].keys() if data else [])],
        "rows": data,
        "fields": list(data[0].keys()) if data else [],
    }
    return None