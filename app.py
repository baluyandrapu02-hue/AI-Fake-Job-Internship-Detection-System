from urllib.parse import urlparse
import json
import os
import re
from datetime import datetime

import joblib
import tldextract
import whois
from flask import Flask, render_template, request, redirect, session, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Render/local friendly configuration
app.secret_key = os.environ.get("SECRET_KEY", "fakejobproject")

database_url = os.environ.get("DATABASE_URL", "sqlite:///users.db")
# Render sometimes gives postgres://, SQLAlchemy needs postgresql://
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

model = None
vectorizer = None
fake_keyword_weights = []

try:
    if os.path.exists("model.pkl") and os.path.exists("vectorizer.pkl"):
        model = joblib.load("model.pkl")
        vectorizer = joblib.load("vectorizer.pkl")

        if model is not None and vectorizer is not None:
            try:
                feature_names = vectorizer.get_feature_names_out()
                coefficients = model.coef_[0]

                fake_keyword_weights = sorted(
                    zip(coefficients, feature_names),
                    reverse=True
                )[:20]
            except Exception as e:
                print("Keyword Explanation Error:", e)

        print("ML model loaded successfully ✅")
    else:
        print("ML model files not found. Running rule-based mode only.")
except Exception as e:
    print("ML model loading error:", e)


# =========================
# DATABASE MODELS
# =========================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(100))
    risk_score = db.Column(db.Integer)
    confidence = db.Column(db.Integer)
    reasons = db.Column(db.Text)
    highlighted_keywords = db.Column(db.Text)
    company_status = db.Column(db.String(200))
    link_analysis = db.Column(db.String(200))
    alternatives = db.Column(db.Text)
    opportunity_type = db.Column(db.String(50))
    scan_date = db.Column(db.String(50))
    scan_time = db.Column(db.String(50))
    favorite = db.Column(db.Boolean, default=False)


with app.app_context():
    db.create_all()


# =========================
# TRUSTED COMPANIES + DOMAINS
# =========================
trusted_companies = [
    "tata consultancy services", "tcs", "infosys", "wipro", "hcl",
    "hcl technologies", "tech mahindra", "mahindra", "accenture",
    "cognizant", "capgemini", "ibm", "deloitte", "amazon", "google",
    "microsoft", "meta", "apple", "oracle", "zoho", "adobe", "intel",
    "salesforce", "netflix", "flipkart", "paytm", "swiggy", "zomato",
    "razorpay", "freshworks", "phonepe", "paypal", "uber", "ola",
    "bosch", "sap", "ey", "kpmg", "pwc", "myntra", "byju's"
]

company_domains = {
    "tata consultancy services": ["tcs.com"],
    "tcs": ["tcs.com"],
    "infosys": ["infosys.com"],
    "wipro": ["wipro.com"],
    "hcl": ["hcltech.com", "hcl.com"],
    "hcl technologies": ["hcltech.com", "hcl.com"],
    "tech mahindra": ["techmahindra.com"],
    "mahindra": ["mahindra.com", "techmahindra.com"],
    "accenture": ["accenture.com"],
    "cognizant": ["cognizant.com"],
    "capgemini": ["capgemini.com"],
    "ibm": ["ibm.com"],
    "deloitte": ["deloitte.com"],
    "amazon": ["amazon.jobs", "amazon.com"],
    "google": ["google.com", "careers.google.com"],
    "microsoft": ["microsoft.com", "careers.microsoft.com"],
    "meta": ["meta.com", "facebook.com"],
    "apple": ["apple.com"],
    "oracle": ["oracle.com"],
    "zoho": ["zoho.com"],
    "adobe": ["adobe.com"],
    "intel": ["intel.com"],
    "salesforce": ["salesforce.com"],
    "netflix": ["jobs.netflix.com", "netflix.com"],
    "flipkart": ["flipkartcareers.com", "flipkart.com"],
    "paytm": ["paytm.com"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],
    "razorpay": ["razorpay.com"],
    "freshworks": ["freshworks.com"],
    "phonepe": ["phonepe.com"],
    "paypal": ["paypal.com"],
    "uber": ["uber.com"],
    "ola": ["olacabs.com"],
    "bosch": ["bosch.com"],
    "sap": ["sap.com"],
    "ey": ["ey.com"],
    "kpmg": ["kpmg.com"],
    "pwc": ["pwc.com"],
    "myntra": ["myntra.com"],
    "byju's": ["byjus.com"]
}


# =========================
# HELPER FUNCTIONS
# =========================
def safe_json_loads(value, default=None):
    if default is None:
        default = []
    try:
        return json.loads(value) if value else default
    except Exception:
        return default


def password_matches(stored_password, entered_password):
    """Supports both old plain-text demo passwords and new hashed passwords."""
    if not stored_password:
        return False

    if stored_password.startswith("scrypt:") or stored_password.startswith("pbkdf2:"):
        try:
            return check_password_hash(stored_password, entered_password)
        except Exception:
            return False

    return stored_password == entered_password


def escape_pdf_text(text):
    text = str(text or "")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def wrap_pdf_lines(text, width=85):
    text = str(text or "")
    lines = []
    for raw_line in text.splitlines() or [text]:
        raw_line = raw_line.strip()
        while len(raw_line) > width:
            lines.append(raw_line[:width])
            raw_line = raw_line[width:]
        lines.append(raw_line)
    return lines


def build_simple_pdf(title, lines):
    """Creates a simple text PDF without extra libraries."""
    pdf_lines = [title, ""]
    for item in lines:
        pdf_lines.extend(wrap_pdf_lines(item))

    pdf_lines = pdf_lines[:42]

    y = 780
    content_parts = ["BT", "/F1 11 Tf"]
    for line in pdf_lines:
        safe_line = escape_pdf_text(line)
        content_parts.append(f"1 0 0 1 50 {y} Tm ({safe_line}) Tj")
        y -= 17
    content_parts.append("ET")
    stream = "\n".join(content_parts)

    objects = []
    objects.append("1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj")
    objects.append("2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj")
    objects.append("3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj")
    objects.append("4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj")
    objects.append(f"5 0 obj << /Length {len(stream.encode('utf-8'))} >> stream\n{stream}\nendstream endobj")

    pdf = "%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf.encode("utf-8")))
        pdf += obj + "\n"

    xref_offset = len(pdf.encode("utf-8"))
    pdf += f"xref\n0 {len(objects) + 1}\n"
    pdf += "0000000000 65535 f \n"
    for offset in offsets[1:]:
        pdf += f"{offset:010d} 00000 n \n"
    pdf += f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF"

    return pdf.encode("utf-8")


def extract_first_url(text):
    urls = re.findall(r"https?://[^\s]+|www\.[^\s]+", text)
    return urls[0] if urls else ""


def check_domain_age(text):
    try:
        url = extract_first_url(text)

        if not url:
            return "Domain age unavailable", 0, []

        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        if not extracted.domain or not extracted.suffix:
            return "Domain age unavailable", 0, []

        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return "Domain age unavailable", 0, []

        age_days = (datetime.now() - creation_date).days
        domain_age_info = f"Domain Age: {age_days} days"

        domain_reasons = []
        extra_risk = 0

        if age_days < 30:
            extra_risk = 30
            domain_reasons.append("Newly registered domain detected (less than 30 days old)")
        elif age_days < 90:
            extra_risk = 15
            domain_reasons.append("Recently registered domain detected")

        return domain_age_info, extra_risk, domain_reasons

    except Exception:
        return "Domain age unavailable", 0, []


def verify_company_and_domain(job_text, application_link=""):
    text = job_text.lower() if job_text else ""
    link = application_link.strip().lower() if application_link else ""

    detected_company = None
    official_match = False
    verification_notes = []
    company_status = "Unknown Company — Verify manually"

    for company in trusted_companies:
        if company in text:
            detected_company = company
            break

    if not detected_company:
        if link:
            verification_notes.append("No trusted company name detected in the posting.")
        return {
            "detected_company": None,
            "company_status": company_status,
            "official_match": False,
            "verification_notes": verification_notes
        }

    pretty_company = detected_company.title()
    company_status = f"Trusted / Known Company Mentioned: {pretty_company}"
    verification_notes.append(f"Detected company name: {pretty_company}")

    if not link:
        verification_notes.append("No application link provided for official domain verification.")
        return {
            "detected_company": detected_company,
            "company_status": company_status,
            "official_match": False,
            "verification_notes": verification_notes
        }

    try:
        parsed = urlparse(link if link.startswith("http") else "https://" + link)
        domain = parsed.netloc.lower().replace("www.", "")
    except Exception:
        domain = ""

    if not domain:
        verification_notes.append("Could not extract a valid domain from the application link.")
        return {
            "detected_company": detected_company,
            "company_status": company_status,
            "official_match": False,
            "verification_notes": verification_notes
        }

    verification_notes.append(f"Application domain found: {domain}")

    official_domains = company_domains.get(detected_company, [])

    for official_domain in official_domains:
        if official_domain in domain:
            official_match = True
            break

    if official_match:
        verification_notes.append("Application link matches the official company domain.")
        company_status = f"Official Company Domain Match Found for {pretty_company}"
    else:
        verification_notes.append(
            "Company name is trusted, but the application link does not match known official company domains."
        )
        company_status = "Company Mentioned but Domain Mismatch — Verify Carefully"

    return {
        "detected_company": detected_company,
        "company_status": company_status,
        "official_match": official_match,
        "verification_notes": verification_notes
    }


# =========================
# MAIN HOME / SCAN ROUTE
# =========================
@app.template_filter("from_json")
def from_json_filter(value):
    return safe_json_loads(value, [])


@limiter.limit("10 per minute")
@app.route("/", methods=["GET", "POST"])
def home():
    if "user" not in session:
        return redirect("/login")

    result = ""
    risk_score = ""
    confidence = ""
    reasons = []
    trust_indicators = []
    opportunity_type = ""
    company_status = ""
    alternatives = []
    link_analysis = ""
    highlighted_keywords = []
    current_date = ""
    current_time = ""

    if request.method == "POST":
        text = request.form.get("job", "").lower()

        if not text.strip():
            result = "Invalid Input"
            reasons.append("Input cannot be empty. Please paste a job or internship description.")
            return render_template(
                "index.html",
                result=result,
                risk_score=0,
                confidence=0,
                current_date="",
                current_time="",
                reasons=reasons,
                highlighted_keywords=highlighted_keywords,
                trust_indicators=trust_indicators,
                opportunity_type="",
                company_status="",
                alternatives=[],
                link_analysis="",
                username=session["user"],
            )

        if len(text.strip()) < 30:
            result = "Invalid Input"
            reasons.append("Input is too short. Please enter a proper job or internship description.")
            return render_template(
                "index.html",
                result=result,
                risk_score=0,
                confidence=0,
                current_date="",
                current_time="",
                reasons=reasons,
                highlighted_keywords=highlighted_keywords,
                trust_indicators=trust_indicators,
                opportunity_type="",
                company_status="",
                alternatives=[],
                link_analysis="",
                username=session["user"],
            )

        original_text_length = len(text)

        application_link = extract_first_url(text)

        verification_result = verify_company_and_domain(text, application_link)
        company_status = verification_result["company_status"]
        verification_notes = verification_result["verification_notes"]
        reasons.extend(verification_notes)

        if original_text_length > 8000:
            text = text[:4000] + " " + text[-4000:]
            reasons.append(
                "Long description detected. Key beginning and ending sections were analyzed for faster processing."
            )

        risk = 0
        ml_confidence = 0

        # ML ANALYSIS
        if model is not None and vectorizer is not None:
            try:
                sample = vectorizer.transform([text])
                ml_prediction = model.predict(sample)[0]
                ml_confidence = round(model.predict_proba(sample).max() * 100, 2)
                sample_array = sample.toarray()[0]

                matched_keywords = []
                for score, word in fake_keyword_weights:
                    try:
                        word_index = vectorizer.vocabulary_.get(word)
                        if word_index is not None and sample_array[word_index] > 0:
                            matched_keywords.append(word)
                    except Exception:
                        pass

                highlighted_keywords = matched_keywords[:8]

                if ml_prediction == 1:
                    risk += 15
                    reasons.append(
                        f"ML model detected suspicious patterns ({ml_confidence}% confidence)"
                    )
                else:
                    risk = max(0, risk - 5)
                    reasons.append(
                        f"ML model found lower risk patterns ({ml_confidence}% confidence)"
                    )

            except Exception as e:
                print("ML Prediction Error:", e)
                reasons.append("ML model unavailable. Rule-based analysis used.")
        else:
            reasons.append("Rule-based analysis used. ML model not loaded.")

        # KEYWORD HIGHLIGHTING
        suspicious_keywords = [
            "registration fee",
            "payment",
            "whatsapp",
            "telegram",
            "no interview",
            "urgent",
            "instant joining",
            "limited seats",
            "security deposit",
            "processing fee",
            "pay",
            "fee",
        ]

        for keyword in suspicious_keywords:
            if keyword in text and keyword not in highlighted_keywords:
                highlighted_keywords.append(keyword)

        # JOB / INTERNSHIP TYPE
        opportunity_type = "Job"
        if "internship" in text or "intern" in text:
            opportunity_type = "Internship"

        # TRUSTED COMPANY CHECK
        for company in trusted_companies:
            if company in text:
                if "Official Company Domain Match Found" not in company_status:
                    company_status = "Known Company — Verify official website"
                trust_indicators.append("✅ Known Company")
                break

        # LINK ANALYSIS
        if "http" in text or "www" in text:
            link_analysis = "Link detected — analyzing trust signals"

            domain_age_info, domain_risk, domain_reasons = check_domain_age(text)
            link_analysis = f"{link_analysis} | {domain_age_info}"

            risk += domain_risk

            for reason in domain_reasons:
                reasons.append(reason)

            if domain_risk >= 30:
                trust_indicators.append("⚠ New Domain")
            elif domain_risk == 15:
                trust_indicators.append("⚠ Recently Registered Domain")
            elif domain_age_info != "Domain age unavailable":
                trust_indicators.append("✅ Established Domain")

            trusted_platforms = [
                "linkedin.com",
                "internshala.com",
                "naukri.com",
                "indeed.com",
                "foundit.in",
                "aicte-india.org",
                "tcs.com",
                "infosys.com",
                "wipro.com",
                "accenture.com",
                "microsoft.com",
                "google.com",
            ]

            trusted_found = False
            for site in trusted_platforms:
                if site in text:
                    trusted_found = True
                    reasons.append("Trusted platform or official website link detected")
                    break

            if "bit.ly" in text or "tinyurl" in text:
                risk += 25
                reasons.append("Shortened link detected")

            if "forms.gle" in text or "docs.google.com/forms" in text:
                risk += 15
                reasons.append("Application form detected — verify company identity")

            if "wa.me" in text or "t.me" in text:
                risk += 20
                reasons.append("Direct WhatsApp/Telegram link detected")
                trust_indicators.append("❌ WhatsApp/Telegram Contact")

            if trusted_found:
                trust_indicators.append("✅ Official/Trusted Link")
                risk = max(0, risk - 10)

        else:
            link_analysis = "No link detected"

        # PAYMENT / FEE LOGIC
        payment_detected = (
            "registration fee" in text
            or "payment" in text
            or "pay" in text
            or "fee" in text
        )

        trusted_payment_context = (
            "tcs" in text
            or "infosys" in text
            or "wipro" in text
            or "accenture" in text
            or "google" in text
            or "microsoft" in text
            or "official website" in text
            or "careers" in text
            or "assessment" in text
            or "exam" in text
            or "nqt" in text
            or "official" in text
        )

        if payment_detected:
            if trusted_payment_context:
                risk += 5
                reasons.append(
                    "Fee/payment detected, but official hiring signals found — verify details"
                )
            else:
                risk += 25
                reasons.append(
                    "Payment or registration fee mentioned without strong trust signals"
                )
                trust_indicators.append("⚠ Payment/Fee Mentioned")

        # INFORMAL CONTACT / RISK SIGNALS
        if "whatsapp" in text or "telegram" in text:
            risk += 20
            reasons.append("Uses informal contact method")

        if "no interview" in text and opportunity_type == "Job":
            risk += 20
            reasons.append("No interview process mentioned for job")

        if "no interview" in text and opportunity_type == "Internship":
            risk += 5
            reasons.append("Internship without interview — verify manually")

        if "urgent" in text or "instant joining" in text or "limited seats" in text:
            risk += 10
            reasons.append("Urgency pressure words detected")

        # SAFER ALTERNATIVES
        if opportunity_type == "Internship":
            alternatives = [
                {"name": "Internshala", "url": "https://internshala.com"},
                {"name": "LinkedIn Jobs", "url": "https://www.linkedin.com/jobs"},
                {"name": "AICTE Internship Portal", "url": "https://internship.aicte-india.org"},
            ]
        else:
            alternatives = [
                {"name": "LinkedIn Jobs", "url": "https://www.linkedin.com/jobs"},
                {"name": "Naukri", "url": "https://www.naukri.com"},
                {"name": "Indeed India", "url": "https://in.indeed.com"},
                {"name": "Foundit", "url": "https://www.foundit.in"},
            ]

        # FINAL RESULT
        risk = min(100, max(0, risk))

        if risk >= 60:
            result = "High Risk — Verify manually"
        elif risk >= 30:
            result = "Proceed Carefully"
        else:
            result = "Low Risk"

        risk_score = risk
        confidence = min(95, max(60 + risk, int(ml_confidence)))

        now = datetime.now()
        current_date = now.strftime("%d %b %Y")
        current_time = now.strftime("%I:%M %p")

        # SAVE TO HISTORY
        new_scan = ScanHistory(
            username=session["user"],
            content=text,
            result=result,
            risk_score=risk_score,
            confidence=confidence,
            reasons=json.dumps(reasons),
            highlighted_keywords=json.dumps(highlighted_keywords),
            company_status=company_status,
            link_analysis=link_analysis,
            alternatives=json.dumps(alternatives),
            opportunity_type=opportunity_type,
            scan_date=current_date,
            scan_time=current_time,
        )

        try:
            db.session.add(new_scan)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print("Database Save Error:", e)
            reasons.append(
                "Scan completed, but history could not be saved due to a database issue."
            )

    return render_template(
        "index.html",
        result=result,
        risk_score=risk_score,
        confidence=confidence,
        current_date=current_date,
        current_time=current_time,
        reasons=reasons,
        highlighted_keywords=highlighted_keywords,
        trust_indicators=trust_indicators,
        opportunity_type=opportunity_type,
        company_status=company_status,
        alternatives=alternatives,
        link_analysis=link_analysis,
        username=session["user"],
    )


# =========================
# ADMIN DASHBOARD
# =========================
@app.route("/admin")
def admin_dashboard():
    if "user" not in session:
        return redirect("/login")

    if session["user"].lower() != "admin":
        return redirect("/")

    scans = ScanHistory.query.order_by(ScanHistory.id.desc()).all()

    total_scans = len(scans)
    high_risk = 0
    medium_risk = 0
    low_risk = 0

    for scan in scans:
        if scan.result and "High Risk" in scan.result:
            high_risk += 1
        elif scan.result and "Proceed Carefully" in scan.result:
            medium_risk += 1
        else:
            low_risk += 1

    recent_scans = scans[:10]

    return render_template(
        "admin.html",
        total_scans=total_scans,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        recent_scans=recent_scans,
    )


# =========================
# HISTORY PAGE
# =========================
@app.route("/history")
def history():
    if "user" not in session:
        return redirect("/login")

    scans = (
        ScanHistory.query.filter_by(username=session["user"])
        .order_by(ScanHistory.id.desc())
        .all()
    )

    favorite_scans = (
        ScanHistory.query.filter_by(username=session["user"], favorite=True)
        .order_by(ScanHistory.id.desc())
        .all()
    )

    total_scans = len(scans)
    low_count = 0
    medium_count = 0
    high_count = 0

    for scan in scans:
        if scan.result and "High Risk" in scan.result:
            high_count += 1
        elif scan.result and "Proceed Carefully" in scan.result:
            medium_count += 1
        else:
            low_count += 1

    return render_template(
        "history.html",
        scans=scans,
        favorite_scans=favorite_scans,
        total_scans=total_scans,
        low_count=low_count,
        medium_count=medium_count,
        high_count=high_count,
    )


# =========================
# FAVORITES PAGE
# =========================
@app.route("/favorites")
def favorites():
    if "user" not in session:
        return redirect("/login")

    scans = (
        ScanHistory.query.filter_by(username=session["user"], favorite=True)
        .order_by(ScanHistory.id.desc())
        .all()
    )

    return render_template("favorites.html", scans=scans)


@app.route("/favorite/<int:id>")
def favorite_scan(id):
    if "user" not in session:
        return redirect("/login")

    scan = ScanHistory.query.filter_by(id=id, username=session["user"]).first_or_404()
    scan.favorite = not scan.favorite
    db.session.commit()

    return redirect("/history")


# =========================
# DELETE ROUTES
# =========================
@app.route("/delete-scan/<int:scan_id>")
def delete_scan(scan_id):
    if "user" not in session:
        return redirect("/login")

    scan = ScanHistory.query.filter_by(
        id=scan_id,
        username=session["user"],
    ).first()

    if scan:
        db.session.delete(scan)
        db.session.commit()

    return redirect("/history")


@app.route("/delete-all-history")
def delete_all_history():
    if "user" not in session:
        return redirect("/login")

    ScanHistory.query.filter_by(username=session["user"]).delete()
    db.session.commit()

    return redirect("/history")


# =========================
# SCAN DETAIL PAGE
# =========================
@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    if "user" not in session:
        return redirect("/login")

    scan = ScanHistory.query.filter_by(
        id=scan_id,
        username=session["user"],
    ).first()

    if not scan:
        return redirect("/history")

    reasons = safe_json_loads(scan.reasons, [])
    alternatives = safe_json_loads(scan.alternatives, [])

    return render_template(
        "scan_detail.html",
        scan=scan,
        reasons=reasons,
        alternatives=alternatives,
    )


# =========================
# PDF EXPORT ROUTES
# =========================
@app.route("/download-pdf/<int:scan_id>")
@app.route("/export-pdf/<int:scan_id>")
def download_pdf(scan_id):
    if "user" not in session:
        return redirect("/login")

    scan = ScanHistory.query.filter_by(
        id=scan_id,
        username=session["user"],
    ).first()

    if not scan:
        return redirect("/history")

    reasons = safe_json_loads(scan.reasons, [])
    highlighted_keywords = safe_json_loads(scan.highlighted_keywords, [])

    pdf_lines = [
        f"User: {scan.username}",
        f"Scan Date: {scan.scan_date or ''} {scan.scan_time or ''}",
        f"Opportunity Type: {scan.opportunity_type or 'N/A'}",
        f"Result: {scan.result or 'N/A'}",
        f"Risk Score: {scan.risk_score if scan.risk_score is not None else 'N/A'}",
        f"Confidence: {scan.confidence if scan.confidence is not None else 'N/A'}%",
        f"Company Status: {scan.company_status or 'N/A'}",
        f"Link Analysis: {scan.link_analysis or 'N/A'}",
        "",
        "Suspicious / Important Keywords:",
        ", ".join(highlighted_keywords) if highlighted_keywords else "None",
        "",
        "Reasons:",
    ]

    if reasons:
        for idx, reason in enumerate(reasons, start=1):
            pdf_lines.append(f"{idx}. {reason}")
    else:
        pdf_lines.append("No reasons available")

    pdf_lines.extend([
        "",
        "Scanned Content Preview:",
        (scan.content or "")[:1200],
    ])

    pdf_bytes = build_simple_pdf("Fake Job & Internship Detection Report", pdf_lines)

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=scan_report_{scan.id}.pdf"
    return response


# =========================
# AUTH ROUTES
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and password_matches(user.password, password):
            session["user"] = username
            return redirect("/")
        else:
            message = "Invalid username or password"

    return render_template("login.html", message=message)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    message = ""

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            message = "Username already exists"
        else:
            new_user = User(username=username, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            message = "Signup successful. Please login."

    return render_template("signup.html", message=message)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = ""

    if request.method == "POST":

        username = request.form["username"].strip()
        new_password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            message = "Password reset successful"
        else:
            message = "Username not found"

    return render_template("forgot_password.html", message=message)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)