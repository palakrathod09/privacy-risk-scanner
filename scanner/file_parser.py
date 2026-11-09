"""
Extracts plain text from supported document types so the detection
engine has a single uniform input to scan.
"""
import csv
import io
import os

SUPPORTED_EXTENSIONS = {".txt", ".md", ".csv", ".pdf", ".docx", ".xlsx", ".log", ".json"}


def extract_text(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()

    if ext in (".txt", ".md", ".log", ".json"):
        return _read_plain(filepath)

    if ext == ".csv":
        return _read_csv(filepath)

    if ext == ".pdf":
        return _read_pdf(filepath)

    if ext == ".docx":
        return _read_docx(filepath)

    if ext == ".xlsx":
        return _read_xlsx(filepath)

    raise ValueError(f"Unsupported file type: {ext}")


def _read_plain(filepath: str) -> str:
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def _read_csv(filepath: str) -> str:
    lines = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            lines.append(", ".join(row))
    return "\n".join(lines)


def _read_pdf(filepath: str) -> str:
    import pdfplumber
    text_parts = []
    with pdfplumber.open(filepath) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text() or ""
            text_parts.append(page_text)
    return "\n".join(text_parts)


def _read_docx(filepath: str) -> str:
    import docx
    d = docx.Document(filepath)
    parts = [p.text for p in d.paragraphs]
    for table in d.tables:
        for row in table.rows:
            parts.append(" | ".join(cell.text for cell in row.cells))
    return "\n".join(parts)


def _read_xlsx(filepath: str) -> str:
    import openpyxl
    wb = openpyxl.load_workbook(filepath, data_only=True)
    lines = []
    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            lines.append(", ".join("" if c is None else str(c) for c in row))
    return "\n".join(lines)
