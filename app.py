"""
BulkVerify — Flask Application
Supports: file upload (15 formats), direct paste, JSON API
"""

import os, io, csv, json, uuid, time, threading
from pathlib import Path
from flask import (Flask, request, jsonify, render_template,
                   send_file, Response, stream_with_context)
from flask_cors import CORS

from core.parser import parse_file, parse_raw_text, SUPPORTED_EXTENSIONS
from core.validator import validate_batch

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
CORS(app)

UPLOAD_FOLDER = Path("uploads")
EXPORT_FOLDER = Path("exports")
UPLOAD_FOLDER.mkdir(exist_ok=True)
EXPORT_FOLDER.mkdir(exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB

_jobs: dict = {}
_lock = threading.Lock()


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html",
                           supported=", ".join(e.lstrip(".").upper() for e in SUPPORTED_EXTENSIONS))

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ── Shared job runner ──────────────────────────────────────────────────────────

def _start_job(emails: list, sources: list, errors: list, check_dns: bool) -> str:
    job_id = str(uuid.uuid4())
    deduped = list({e.strip().lower() for e in emails if e.strip()})
    with _lock:
        _jobs[job_id] = {
            "status": "processing", "total": len(deduped),
            "done": 0, "results": [], "sources": sources,
            "errors": errors, "started_at": time.time(),
        }

    def run():
        def cb(done, total):
            with _lock:
                if job_id in _jobs:
                    _jobs[job_id]["done"] = done
        try:
            results = validate_batch(deduped, check_dns=check_dns,
                                     max_workers=30, progress_cb=cb)
            with _lock:
                _jobs[job_id].update({"results": results, "status": "done",
                                      "done": len(deduped)})
        except Exception as e:
            with _lock:
                _jobs[job_id].update({"status": "error", "error": str(e)})

    threading.Thread(target=run, daemon=True).start()
    return job_id


# ── File upload ────────────────────────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
def upload():
    files = request.files.getlist("files")
    check_dns = request.form.get("check_dns", "true").lower() == "true"

    if not files or all(not f.filename for f in files):
        return jsonify({"error": "No files provided"}), 400

    all_emails, sources, errors = [], [], []
    for f in files:
        if not f or not f.filename:
            continue
        raw = f.read()
        emails, err = parse_file(f.filename, raw)
        if err:
            errors.append(err)
        all_emails.extend(emails)
        sources.append({"name": f.filename, "raw_count": len(emails)})

    if not all_emails:
        return jsonify({"error": "No emails found in uploaded files",
                        "details": errors}), 400

    job_id = _start_job(all_emails, sources, errors, check_dns)
    with _lock:
        total = _jobs[job_id]["total"]
    return jsonify({"job_id": job_id, "total": total, "sources": sources})


# ── Direct paste ───────────────────────────────────────────────────────────────

@app.route("/api/paste", methods=["POST"])
def paste():
    """Accept raw text (form field or JSON body) and start a validation job."""
    check_dns = True
    text = ""

    if request.is_json:
        body = request.get_json(silent=True) or {}
        text = body.get("text", "") or body.get("emails", "")
        check_dns = body.get("check_dns", True)
    else:
        text = request.form.get("text", "")
        check_dns = request.form.get("check_dns", "true").lower() == "true"

    if not text or not text.strip():
        return jsonify({"error": "No text provided"}), 400

    emails = parse_raw_text(text)
    if not emails:
        return jsonify({"error": "No valid email addresses found in pasted text"}), 400

    sources = [{"name": "Pasted text", "raw_count": len(emails)}]
    job_id = _start_job(emails, sources, [], check_dns)
    with _lock:
        total = _jobs[job_id]["total"]
    return jsonify({"job_id": job_id, "total": total, "sources": sources})


# ── REST API endpoint (JSON in/out, no UI) ─────────────────────────────────────

@app.route("/api/validate", methods=["POST"])
def api_validate():
    """
    Synchronous REST API — validates up to 5,000 emails inline (no job polling).
    POST JSON: {"emails": ["a@b.com", ...], "check_dns": true}
    Returns full results immediately.
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    body = request.get_json(silent=True) or {}
    emails = body.get("emails", [])
    check_dns = body.get("check_dns", False)  # default off for sync speed

    if not emails:
        return jsonify({"error": "'emails' list is required"}), 400
    if len(emails) > 5000:
        return jsonify({"error": "Max 5,000 emails per sync request. Use /api/upload for larger batches."}), 400

    results = validate_batch(emails, check_dns=check_dns, max_workers=20)
    stats = _compute_stats(results)
    return jsonify({"total": len(results), "stats": stats, "results": results})


# ── Job status & streaming ─────────────────────────────────────────────────────

@app.route("/api/job/<job_id>")
def job_status(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    resp = {"status": job["status"], "total": job["total"],
            "done": job["done"], "sources": job["sources"],
            "errors": job["errors"]}
    if job["status"] == "done":
        resp["stats"] = _compute_stats(job["results"])
        resp["results"] = job["results"]
    return jsonify(resp)


@app.route("/api/job/<job_id>/stream")
def job_stream(job_id):
    def generate():
        while True:
            with _lock:
                job = _jobs.get(job_id)
            if not job:
                yield f"data: {json.dumps({'error': 'not found'})}\n\n"; break
            pct = int(job["done"] / max(job["total"], 1) * 100)
            payload = {"status": job["status"], "done": job["done"],
                       "total": job["total"], "pct": pct}
            if job["status"] == "done":
                payload["stats"] = _compute_stats(job["results"])
            yield f"data: {json.dumps(payload)}\n\n"
            if job["status"] in ("done", "error"):
                break
            time.sleep(0.5)
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Filtered email list ────────────────────────────────────────────────────────

@app.route("/api/job/<job_id>/emails")
def job_emails(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "Not ready"}), 404

    legitimacy = request.args.get("legitimacy")
    activity   = request.args.get("activity")
    search     = request.args.get("q", "").lower()
    page       = int(request.args.get("page", 1))
    per_page   = min(int(request.args.get("per_page", 100)), 500)

    rows = job["results"]
    if legitimacy:
        rows = [r for r in rows if r["legitimacy"] == legitimacy]
    if activity:
        rows = [r for r in rows if r["activity"] == activity]
    if search:
        rows = [r for r in rows if search in r["email"]]

    total = len(rows)
    start = (page - 1) * per_page
    return jsonify({"total": total, "page": page, "per_page": per_page,
                    "pages": max(1, (total + per_page - 1) // per_page),
                    "emails": rows[start: start + per_page]})


# ── Export ─────────────────────────────────────────────────────────────────────

@app.route("/api/job/<job_id>/export")
def export_csv(job_id):
    with _lock:
        job = _jobs.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "Not ready"}), 404

    legitimacy = request.args.get("legitimacy")
    activity   = request.args.get("activity")
    rows = job["results"]
    if legitimacy:
        rows = [r for r in rows if r["legitimacy"] == legitimacy]
    if activity:
        rows = [r for r in rows if r["activity"] == activity]

    output = io.StringIO()
    fields = ["email","domain","tld","legitimacy","activity","score",
              "is_disposable","is_role","is_free_provider",
              "mx_records","domain_exists","syntax_valid","risk_flags","syntax_issues"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        r2 = dict(r)
        r2["mx_records"]    = "|".join(r.get("mx_records", []))
        r2["risk_flags"]    = "|".join(r.get("risk_flags", []))
        r2["syntax_issues"] = "|".join(r.get("syntax_issues", []))
        writer.writerow({k: r2.get(k, "") for k in fields})

    output.seek(0)
    suf = (f"_{legitimacy}" if legitimacy else "") + (f"_{activity}" if activity else "")
    return send_file(io.BytesIO(output.getvalue().encode()),
                     mimetype="text/csv", as_attachment=True,
                     download_name=f"emails{suf}_{job_id[:8]}.csv")


# ── Stats helper ───────────────────────────────────────────────────────────────

def _compute_stats(results):
    total   = len(results)
    valid   = sum(1 for r in results if r["legitimacy"] == "valid")
    risky   = sum(1 for r in results if r["legitimacy"] == "risky")
    invalid = sum(1 for r in results if r["legitimacy"] == "invalid")
    active  = sum(1 for r in results if r["activity"] == "active")
    inactive= sum(1 for r in results if r["activity"] == "inactive")

    domain_map: dict = {}
    for r in results:
        d = r.get("domain", "")
        if d:
            domain_map[d] = domain_map.get(d, 0) + 1

    flag_map: dict = {}
    for r in results:
        for f in r.get("risk_flags", []):
            flag_map[f] = flag_map.get(f, 0) + 1

    def pct(n): return round(n / total * 100, 1) if total else 0
    return {
        "total": total, "valid": valid, "valid_pct": pct(valid),
        "risky": risky, "risky_pct": pct(risky),
        "invalid": invalid, "invalid_pct": pct(invalid),
        "active": active, "active_pct": pct(active),
        "inactive": inactive, "inactive_pct": pct(inactive),
        "top_domains": [{"domain": d, "count": c}
                        for d, c in sorted(domain_map.items(), key=lambda x: -x[1])[:20]],
        "risk_flags": sorted(flag_map.items(), key=lambda x: -x[1]),
    }


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "jobs": len(_jobs),
                    "supported_formats": SUPPORTED_EXTENSIONS})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
