# Privacy Risk Scanner for Documents

A local web tool that scans documents (`.txt`, `.md`, `.csv`, `.pdf`, `.docx`, `.xlsx`, `.log`, `.json`)
for common categories of sensitive/personally identifiable information (PII) and displays
the results on an interactive risk dashboard (gauge, charts, per-file and per-finding tables).

Everything runs **100% locally** — no data leaves your machine, and uploaded files are
deleted from disk immediately after scanning (only redacted findings are kept in memory
for the session).

## What it detects

| Category | Severity |
|---|---|
| Emails | Medium |
| Phone numbers | Medium |
| Physical street addresses | Medium |
| Driver's license numbers | Medium |
| SSNs (US) | Critical |
| Credit card numbers (Luhn-validated) | Critical |
| AWS access keys | Critical |
| Private key blocks (PEM) | Critical |
| IBANs | High |
| Bank account/routing numbers | High |
| Passport numbers | High |
| Dates of birth | High |
| Generic API keys / secrets / passwords | High |
| Medical record references | High |
| IPv4 addresses | Low |

Scoring combines findings using severity weights into a single 0–100 risk score
(with diminishing returns so score doesn't blow past 100 on large files) and buckets
into **Low / Medium / High / Critical**.

## Running it in VS Code

1. **Unzip** this project and open the folder in VS Code (`File → Open Folder…`).
2. Open a terminal in VS Code (`` Ctrl+` `` / `` Cmd+` ``).
3. Create and activate a virtual environment (recommended):

   ```bash
   python -m venv .venv

   # macOS / Linux
   source .venv/bin/activate

   # Windows (PowerShell)
   .venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Run the app:

   ```bash
   python app.py
   ```

6. Open your browser to **http://127.0.0.1:5000**

7. Try it out on the included sample file at `sample_docs/sample_customer_record.txt`
   (contains fake/synthetic data only) to see the dashboard populate.

> Tip: install the VS Code "Python" extension for linting/debugging, and use the
> Run and Debug panel with `app.py` as the entry point if you'd rather not use the terminal.

## Project structure

```
privacy-risk-scanner/
├── app.py                     # Flask app & routes
├── requirements.txt
├── scanner/
│   ├── detectors.py           # Regex/checksum detectors + risk scoring
│   └── file_parser.py         # Extracts text from txt/pdf/docx/xlsx/csv
├── templates/
│   ├── base.html
│   ├── index.html             # Upload page
│   ├── results.html           # Dashboard (charts + tables)
│   └── history.html           # Session scan history
├── static/
│   ├── css/style.css
│   └── js/{upload.js, dashboard.js}
├── sample_docs/                # Synthetic test file with fake PII
└── uploads/                    # Scratch dir; files are deleted right after scanning
```

## Extending it

- Add new patterns in `scanner/detectors.py` → `PATTERNS` list (category, severity, regex, optional validator function).
- Adjust scoring in `score_findings()` in the same file.
- Add new file types by extending `SUPPORTED_EXTENSIONS` and `extract_text()` in `scanner/file_parser.py`.

## Notes & limitations

- Detection is regex/heuristic-based (no ML/NLP), so it will have false positives/negatives —
  it's meant as a fast triage tool, not a certified compliance scanner.
- Scan history is kept in memory only and resets when you stop the app.
- For production use, set a real `app.secret_key` via environment variable and consider adding
  authentication if exposing beyond localhost.
