#!/usr/bin/env python3
"""
server.py — ClearBounce Web UI Server
Run:  python3 server.py
Then open: http://127.0.0.1:8080
"""

import csv
import io
import json
import os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, Response
from email_engine import validate_email, EmailStatus

app = Flask(__name__)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

EMAIL_COL_NAMES = [
    "email id", "email", "email address", "emailid", "e-mail",
    "e mail", "mail", "emailaddress", "email_id", "lead email",
]

jobs = {}
jobs_lock = threading.Lock()


def find_email_column(headers):
    for h in headers:
        if h.strip().lower() in EMAIL_COL_NAMES:
            return h
    for h in headers:
        if "email" in h.lower() or "e-mail" in h.lower():
            return h
    return None


def status_label(status):
    return {
        EmailStatus.VALID:      "Valid",
        EmailStatus.INVALID:    "Invalid",
        EmailStatus.CATCHALL:   "Catch-All (send with caution)",
        EmailStatus.UNKNOWN:    "Unknown",
        EmailStatus.DISPOSABLE: "Disposable (do not send)",
        EmailStatus.RISKY:      "Risky (role-based)",
    }.get(status, "Unknown")


def parse_csv(file_bytes):
    for enc in ["utf-8-sig", "utf-8", "latin-1", "cp1252"]:
        try:
            text = file_bytes.decode(enc)
            sample = text[:4096]
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            reader  = csv.DictReader(io.StringIO(text), dialect=dialect)
            headers = list(reader.fieldnames or [])
            rows    = list(reader)
            return headers, rows
        except Exception:
            continue
    raise ValueError("Could not read CSV file")


@app.route("/")
def index():
    import os
    index_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        return f.read(), 200, {"Content-Type": "text/html"}


@app.route("/api/verify/single", methods=["POST"])
def verify_single():
    data  = request.json or {}
    email = (data.get("email") or "").strip()
    if not email:
        return jsonify({"error": "No email provided"}), 400
    r = validate_email(email, skip_smtp=data.get("fast", False))
    return jsonify(r.to_dict())


@app.route("/api/verify/bulk/upload", methods=["POST"])
def verify_bulk_upload():
    fast = request.form.get("fast", "false").lower() == "true"
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f          = request.files["file"]
    file_bytes = f.read()
    filename   = f.filename or "upload.csv"

    try:
        headers, rows = parse_csv(file_bytes)
    except Exception as e:
        return jsonify({"error": f"Could not read file: {e}"}), 400

    if not rows:
        return jsonify({"error": "File has no data rows"}), 400

    email_col = find_email_column(headers)
    if not email_col:
        return jsonify({
            "error": "Could not find email column. Make sure your CSV has a column named 'Email id', 'Email', or similar.",
            "columns_found": headers
        }), 400

    for row in rows:
        raw   = (row.get(email_col) or "").strip().lower()
        match = EMAIL_RE.search(raw)
        row["_email"] = match.group(0) if match else raw

    unique_emails = list(dict.fromkeys(
        r["_email"] for r in rows if "@" in r.get("_email", "")
    ))

    if not unique_emails:
        return jsonify({"error": f"No valid email addresses found in column '{email_col}'"}), 400

    job_id = str(uuid.uuid4())
    with jobs_lock:
        jobs[job_id] = {
            "total": len(unique_emails), "done": 0,
            "results": {}, "finished": False, "error": None,
            "headers": headers, "rows": rows,
            "email_col": email_col, "filename": filename,
        }

    def run_job():
        result_map = {}
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(validate_email, e, skip_smtp=fast): e for e in unique_emails}
            for future in as_completed(futures):
                email = futures[future]
                try:
                    r = future.result()
                    result_map[email] = r.to_dict()
                    result_map[email]["_status_label"] = status_label(r.status)
                except Exception as exc:
                    result_map[email] = {
                        "email": email, "status": "unknown",
                        "confidence_score": 0,
                        "_status_label": "Unknown",
                        "error": str(exc)
                    }
                with jobs_lock:
                    jobs[job_id]["done"]   += 1
                    jobs[job_id]["results"] = result_map
        with jobs_lock:
            jobs[job_id]["finished"] = True

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({
        "job_id": job_id, "total": len(unique_emails),
        "email_col": email_col, "columns": len(headers), "rows": len(rows),
    })


@app.route("/api/verify/bulk/status/<job_id>")
def bulk_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    results = job["results"]
    counts  = {"valid":0,"invalid":0,"catch-all":0,"unknown":0,"disposable":0,"risky":0}
    for r in results.values():
        s = r.get("status","unknown")
        if s in counts: counts[s] += 1
    return jsonify({
        "total": job["total"], "done": job["done"],
        "finished": job["finished"], "counts": counts,
    })


@app.route("/api/verify/bulk/preview/<job_id>")
def bulk_preview(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    rows    = job["rows"]
    results = job["results"]
    preview = []
    for row in rows[:300]:
        email  = row.get("_email", "")
        result = results.get(email, {})
        preview.append({
            "email":        email,
            "status":       result.get("status", "pending"),
            "score":        result.get("confidence_score", 0),
            "status_label": result.get("_status_label", "Pending..."),
        })
    return jsonify({"rows": preview, "total": len(rows)})


@app.route("/api/verify/bulk/download/<job_id>")
def bulk_download(job_id):
    filter_type = request.args.get("filter", "all")
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if not job["finished"]:
        return jsonify({"error": "Job not finished yet"}), 400

    headers  = job["headers"]
    rows     = job["rows"]
    results  = job["results"]
    filename = job["filename"]

    out_headers = headers + ["Email Status"]
    output      = io.StringIO()
    writer      = csv.DictWriter(output, fieldnames=out_headers,
                                  extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()

    for row in rows:
        email  = row.get("_email", "")
        result = results.get(email)
        label  = result.get("_status_label", "Unknown") if result else (
                 "No email / invalid format" if not email or "@" not in email else "Not checked")

        if filter_type == "valid" and label != "Valid":
            continue

        out_row = {k: row.get(k, "") for k in headers}
        out_row["Email Status"] = label
        writer.writerow(out_row)

    csv_bytes = output.getvalue().encode("utf-8-sig")
    suffix    = "_valid_only" if filter_type == "valid" else "_validated"
    dl_name   = filename.replace(".csv","").replace(".txt","") + suffix + ".csv"

    return Response(csv_bytes, mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{dl_name}"'})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"\n  ClearBounce is running!")
    print(f"  Open this in your browser: http://127.0.0.1:{port}\n")
    app.run(debug=False, host="127.0.0.1", port=port, threaded=True)
