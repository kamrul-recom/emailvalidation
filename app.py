"""
BulkVerify — Flask Application
Supports: file upload (15 formats), direct paste, JSON API
"""

import io
import csv
import json
import re
import time
from pathlib import Path

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    send_file,
    Response,
    stream_with_context,
)
from flask_cors import CORS

from core.config import get_settings
from core.jobs import job_store
from core.parser import parse_file, parse_raw_text, SUPPORTED_EXTENSIONS
from core.pipeline import run_full_pipeline
from core.stats import compute_stats, filter_results
from workers.tasks import enqueue_validation

settings = get_settings()

app = Flask(__name__)
app.secret_key = settings.secret_key
CORS(app)


@app.after_request
def _no_cache_html(response):
    if response.content_type and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


UPLOAD_FOLDER = Path("uploads")
EXPORT_FOLDER = Path("exports")
UPLOAD_FOLDER.mkdir(exist_ok=True)
EXPORT_FOLDER.mkdir(exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

_rate_limit_cache: dict[str, list[float]] = {}


def _sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", Path(name).name)[:200]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _check_rate_limit() -> bool:
    ip = _client_ip()
    now = time.time()
    window = settings.upload_rate_window_seconds
    limit = settings.upload_rate_limit
    hits = _rate_limit_cache.setdefault(ip, [])
    hits[:] = [t for t in hits if now - t < window]
    if len(hits) >= limit:
        return False
    hits.append(now)
    return True


def _start_job(emails: list, sources: list, errors: list, check_dns: bool, use_provider: bool) -> str:
    deduped = list({e.strip().lower() for e in emails if e.strip()})
    job_id = job_store.create_job(deduped, sources, errors)
    enqueue_validation(job_id, deduped, check_dns, use_provider)
    return job_id


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template(
        "index.html",
        supported=", ".join(e.lstrip(".").upper() for e in SUPPORTED_EXTENSIONS),
    )


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ── Config ─────────────────────────────────────────────────────────────────────

@app.route("/api/config")
def api_config():
    return jsonify({
        "supported_formats": list(SUPPORTED_EXTENSIONS),
        "cost_per_email": settings.cost_per_email,
        "prefilter_skip_estimate_pct": settings.prefilter_skip_estimate_pct,
        "use_provider": settings.use_provider,
        "use_prefilter": settings.use_prefilter,
        "use_reacher": settings.use_reacher,
        "reacher_url": settings.reacher_url,
    })


# ── Preview ────────────────────────────────────────────────────────────────────

@app.route("/api/preview", methods=["POST"])
def api_preview():
    files = request.files.getlist("files")
    if not files or all(not f.filename for f in files):
        return jsonify({"error": "No files provided"}), 400

    all_emails, sources, errors = [], [], []
    for f in files:
        if not f or not f.filename:
            continue
        raw = f.read()
        emails, err = parse_file(_sanitize_filename(f.filename), raw)
        if err:
            errors.append(err)
        all_emails.extend(emails)
        sources.append({"name": _sanitize_filename(f.filename), "raw_count": len(emails)})

    unique = list({e.strip().lower() for e in all_emails if e.strip()})
    skip_est = int(len(unique) * settings.prefilter_skip_estimate_pct)
    billable = max(0, len(unique) - skip_est)
    return jsonify({
        "total": len(unique),
        "sources": sources,
        "errors": errors,
        "estimated_skip": skip_est,
        "estimated_billable": billable,
        "estimated_cost_usd": round(billable * settings.cost_per_email, 2),
    })


# ── File upload ────────────────────────────────────────────────────────────────

@app.route("/api/upload", methods=["POST"])
def upload():
    if not _check_rate_limit():
        return jsonify({"error": "Rate limit exceeded — max 5 uploads per hour"}), 429

    files = request.files.getlist("files")
    check_dns = request.form.get("check_dns", "true").lower() == "true"
    use_provider = request.form.get("use_provider", str(settings.use_provider)).lower() == "true"

    if not files or all(not f.filename for f in files):
        return jsonify({"error": "No files provided"}), 400

    all_emails, sources, errors = [], [], []
    for f in files:
        if not f or not f.filename:
            continue
        raw = f.read()
        emails, err = parse_file(_sanitize_filename(f.filename), raw)
        if err:
            errors.append(err)
        all_emails.extend(emails)
        sources.append({"name": _sanitize_filename(f.filename), "raw_count": len(emails)})

    if not all_emails:
        return jsonify({"error": "No emails found in uploaded files", "details": errors}), 400

    job_id = _start_job(all_emails, sources, errors, check_dns, use_provider)
    job = job_store.get_job(job_id)
    return jsonify({"job_id": job_id, "total": job["total"], "sources": sources})


# ── Direct paste ───────────────────────────────────────────────────────────────

@app.route("/api/paste", methods=["POST"])
def paste():
    if not _check_rate_limit():
        return jsonify({"error": "Rate limit exceeded — max 5 uploads per hour"}), 429

    check_dns = True
    use_provider = settings.use_provider
    text = ""

    if request.is_json:
        body = request.get_json(silent=True) or {}
        text = body.get("text", "") or body.get("emails", "")
        check_dns = body.get("check_dns", True)
        use_provider = body.get("use_provider", settings.use_provider)
    else:
        text = request.form.get("text", "")
        check_dns = request.form.get("check_dns", "true").lower() == "true"
        use_provider = request.form.get("use_provider", str(settings.use_provider)).lower() == "true"

    if not text or not text.strip():
        return jsonify({"error": "No text provided"}), 400

    emails = parse_raw_text(text)
    if not emails:
        return jsonify({"error": "No valid email addresses found in pasted text"}), 400

    sources = [{"name": "Pasted text", "raw_count": len(emails)}]
    job_id = _start_job(emails, sources, [], check_dns, use_provider)
    job = job_store.get_job(job_id)
    return jsonify({"job_id": job_id, "total": job["total"], "sources": sources})


# ── REST API endpoint (JSON in/out, no UI) ─────────────────────────────────────

@app.route("/api/validate", methods=["POST"])
def api_validate():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    body = request.get_json(silent=True) or {}
    emails = body.get("emails", [])
    check_dns = body.get("check_dns", False)
    use_provider = body.get("use_provider", settings.use_provider)

    if not emails:
        return jsonify({"error": "'emails' list is required"}), 400
    if len(emails) > 5000:
        return jsonify({"error": "Max 5,000 emails per sync request. Use /api/upload for larger batches."}), 400

    results, api_calls = run_full_pipeline(emails, check_dns=check_dns, use_provider=use_provider)
    stats = compute_stats(results, api_calls)
    return jsonify({"total": len(results), "stats": stats, "results": results})


# ── Job status & streaming ─────────────────────────────────────────────────────

@app.route("/api/job/<job_id>")
def job_status(job_id):
    job = job_store.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    resp = {
        "status": job["status"],
        "total": job["total"],
        "done": job["done"],
        "sources": job["sources"],
        "errors": job["errors"],
        "api_calls_made": job.get("api_calls_made", 0),
    }
    if job["status"] == "done":
        resp["stats"] = job.get("stats") or compute_stats(job.get("results", []), job.get("api_calls_made", 0))
        resp["results"] = job.get("results", [])
    if job["status"] == "error":
        resp["error"] = job.get("error", "")
    return jsonify(resp)


@app.route("/api/job/<job_id>/stats")
def job_stats(job_id):
    job = job_store.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "done":
        return jsonify({"error": "Not ready"}), 404
    stats = job.get("stats") or compute_stats(job.get("results", []), job.get("api_calls_made", 0))
    return jsonify(stats)


@app.route("/api/job/<job_id>/stream")
def job_stream(job_id):
    def generate():
        while True:
            job = job_store.get_job(job_id)
            if not job:
                yield f"data: {json.dumps({'error': 'not found'})}\n\n"
                break
            pct = int(job["done"] / max(job["total"], 1) * 100)
            payload = {
                "status": job["status"],
                "done": job["done"],
                "total": job["total"],
                "pct": pct,
            }
            if job["status"] == "done":
                payload["stats"] = job.get("stats") or compute_stats(
                    job.get("results", []), job.get("api_calls_made", 0)
                )
            yield f"data: {json.dumps(payload)}\n\n"
            if job["status"] in ("done", "error"):
                break
            time.sleep(0.5)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Filtered email list ────────────────────────────────────────────────────────

@app.route("/api/job/<job_id>/emails")
def job_emails(job_id):
    job = job_store.get_job(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "Not ready"}), 404

    legitimacy = request.args.get("legitimacy")
    activity = request.args.get("activity")
    catch_all = request.args.get("catch_all")
    domain_status = request.args.get("domain_status")
    domain_active = request.args.get("domain_active")
    mailbox_exists = request.args.get("mailbox_exists")
    smtp_status = request.args.get("smtp_status")
    search = request.args.get("q", "").lower()
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 100)), 500)

    return jsonify(job_store.get_results_page(
        job_id,
        legitimacy=legitimacy,
        activity=activity,
        catch_all=catch_all,
        domain_status=domain_status,
        domain_active=domain_active,
        mailbox_exists=mailbox_exists,
        smtp_status=smtp_status,
        search=search,
        page=page,
        per_page=per_page,
    ))


# ── Export ─────────────────────────────────────────────────────────────────────

@app.route("/api/job/<job_id>/export")
def export_csv(job_id):
    job = job_store.get_job(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "Not ready"}), 404

    legitimacy = request.args.get("legitimacy")
    activity = request.args.get("activity")
    catch_all = request.args.get("catch_all")
    domain_status = request.args.get("domain_status")
    mailbox_exists = request.args.get("mailbox_exists")
    smtp_status = request.args.get("smtp_status")
    rows = filter_results(
        job.get("results", []),
        legitimacy=legitimacy,
        activity=activity,
        catch_all=catch_all,
        domain_status=domain_status,
        mailbox_exists=mailbox_exists,
        smtp_status=smtp_status,
    )

    output = io.StringIO()
    fields = [
        "email", "domain", "tld", "legitimacy", "activity", "catch_all", "score",
        "domain_pattern_valid", "domain_exists", "domain_active", "domain_status",
        "mailbox_exists", "smtp_status",
        "active_in_days", "provider", "provider_status", "provider_sub_status",
        "needs_api_check", "is_disposable", "is_role", "is_free_provider",
        "mx_records", "ns_records", "syntax_valid", "risk_flags", "syntax_issues",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        r2 = dict(r)
        r2["mx_records"] = "|".join(r.get("mx_records", []) or [])
        r2["ns_records"] = "|".join(r.get("ns_records", []) or [])
        r2["risk_flags"] = "|".join(r.get("risk_flags", []) or [])
        r2["syntax_issues"] = "|".join(r.get("syntax_issues", []) or [])
        if r2.get("catch_all") is None:
            r2["catch_all"] = "unknown"
        writer.writerow({k: r2.get(k, "") for k in fields})

    output.seek(0)
    suf = ""
    if legitimacy:
        suf += f"_{legitimacy}"
    if activity:
        suf += f"_{activity}"
    if catch_all:
        suf += f"_catchall_{catch_all}"
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"emails{suf}_{job_id[:8]}.csv",
    )


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "jobs": job_store.count_jobs(),
        "supported_formats": SUPPORTED_EXTENSIONS,
        "use_provider": settings.use_provider,
        "use_prefilter": settings.use_prefilter,
        "use_reacher": settings.use_reacher,
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000, threaded=True)
