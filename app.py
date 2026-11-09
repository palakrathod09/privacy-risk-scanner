"""
Privacy Risk Scanner for Documents
------------------------------------
A local web tool that scans uploaded documents (txt, pdf, docx, xlsx, csv)
for common categories of sensitive / personally identifiable information,
and renders an interactive risk dashboard.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000
"""
import os
import uuid
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename

from scanner.file_parser import extract_text, SUPPORTED_EXTENSIONS
from scanner.detectors import scan_text, score_findings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB per request

# In-memory store of scan results (per-process). Good enough for a local tool.
SCAN_HISTORY = []


def allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in SUPPORTED_EXTENSIONS


@app.route("/")
def index():
    return render_template("index.html", extensions=sorted(SUPPORTED_EXTENSIONS))


@app.route("/scan", methods=["POST"])
def scan():
    files = request.files.getlist("documents")
    if not files or all(f.filename == "" for f in files):
        flash("Please choose at least one file to scan.", "error")
        return redirect(url_for("index"))

    batch_id = str(uuid.uuid4())[:8]
    batch_findings = []
    file_summaries = []
    skipped = []

    for f in files:
        if f.filename == "":
            continue
        if not allowed_file(f.filename):
            skipped.append(f.filename)
            continue

        safe_name = secure_filename(f.filename)
        temp_path = os.path.join(UPLOAD_DIR, f"{batch_id}_{safe_name}")
        f.save(temp_path)

        try:
            text = extract_text(temp_path)
            findings = scan_text(text, source_name=safe_name)
        except Exception as exc:  # noqa: BLE001 - surface parse errors to UI
            findings = []
            flash(f"Could not parse '{safe_name}': {exc}", "error")
        finally:
            # Remove the uploaded file immediately after scanning; we only
            # keep the extracted findings, never the original document.
            if os.path.exists(temp_path):
                os.remove(temp_path)

        summary = score_findings(findings)
        file_summaries.append({
            "name": safe_name,
            "summary": summary,
            "findings": findings,
        })
        batch_findings.extend(findings)

    if not file_summaries:
        flash("No supported files were scanned. Supported types: " + ", ".join(sorted(SUPPORTED_EXTENSIONS)), "error")
        return redirect(url_for("index"))

    overall = score_findings(batch_findings)
    result = {
        "batch_id": batch_id,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files": file_summaries,
        "overall": overall,
        "findings": batch_findings,
        "skipped": skipped,
    }
    SCAN_HISTORY.insert(0, {
        "batch_id": batch_id,
        "timestamp": result["timestamp"],
        "file_count": len(file_summaries),
        "score": overall["score"],
        "level": overall["level"],
        "total_findings": overall["total"],
    })
    SCAN_HISTORY[:] = SCAN_HISTORY[:20]  # cap history

    return render_template("results.html", result=result)


@app.route("/history")
def history():
    return render_template("history.html", history=SCAN_HISTORY)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
