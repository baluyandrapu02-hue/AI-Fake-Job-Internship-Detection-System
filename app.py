import json
import os
import re
from datetime import datetime

import joblib
import tldextract
import whois
from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
app = Flask(__name__)
app.secret_key = "fakejobproject"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"

db = SQLAlchemy(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)
model = None
vectorizer = None

try:
    if os.path.exists("model.pkl") and os.path.exists("vectorizer.pkl"):
        model = joblib.load("model.pkl")
        vectorizer = joblib.load("vectorizer.pkl")
        print("ML model loaded successfully ✅")
    else:
        print("ML model files not found. Running rule-based mode only.")
except Exception as e:
    print("ML model loading error:", e)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    result = db.Column(db.String(100))
    risk_score = db.Column(db.Integer)
    confidence = db.Column(db.Integer)
    reasons = db.Column(db.Text)
    company_status = db.Column(db.String(200))
    link_analysis = db.Column(db.String(200))
    alternatives = db.Column(db.Text)
    opportunity_type = db.Column(db.String(50))
    scan_date = db.Column(db.String(50))
    scan_time = db.Column(db.String(50))
    favorite = db.Column(db.Boolean, default=False)


with app.app_context():
    db.create_all()


def extract_first_url(text):
    urls = re.findall(r"https?://[^\s]+|www\.[^\s]+", text)
    if urls:
        return urls[0]
    return ""


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
        text = request.form["job"].lower()
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

        if original_text_length > 8000:
            text = text[:4000] + " " + text[-4000:]
            reasons.append(
                "Long description detected. Key beginning and ending sections were analyzed for faster processing."
            )

        risk = 0
        ml_confidence = 0

        if model is not None and vectorizer is not None:
            try:
                sample = vectorizer.transform([text])
                ml_prediction = model.predict(sample)[0]
                ml_confidence = round(model.predict_proba(sample).max() * 100, 2)

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
            if keyword in text:
                highlighted_keywords.append(keyword)

        opportunity_type = "Job"

        if "internship" in text or "intern" in text:
            opportunity_type = "Internship"

        company_status = "Unknown Company — Verify manually"

        trusted_companies = [
            "google",
            "amazon",
            "microsoft",
            "tcs",
            "infosys",
            "wipro",
            "accenture",
            "ibm",
        ]

        for company in trusted_companies:
            if company in text:
                company_status = "Known Company — Verify official website"
                trust_indicators.append("✅ Known Company")
                break

        if "http" in text or "www" in text:
            link_analysis = "Link detected — analyzing trust signals"

            domain_age_info, domain_risk, domain_reasons = check_domain_age(text)

            link_analysis = f"{link_analysis} | {domain_age_info}"

            risk += domain_risk

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

        new_scan = ScanHistory(
            username=session["user"],
            content=text,
            result=result,
            risk_score=risk_score,
            confidence=confidence,
            reasons=json.dumps(reasons),
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
        if "High Risk" in scan.result:
            high_count += 1
        elif "Proceed Carefully" in scan.result:
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

    reasons = json.loads(scan.reasons) if scan.reasons else []
    alternatives = json.loads(scan.alternatives) if scan.alternatives else []

    return render_template(
        "scan_detail.html",
        scan=scan,
        reasons=reasons,
        alternatives=alternatives,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
 
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            session["user"] = username
            return redirect("/")
        else:
            message = "Invalid username or password"

    return render_template("login.html", message=message)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            message = "Username already exists"
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            message = "Signup successful. Please login."

    return render_template("signup.html", message=message)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = ""

    if request.method == "POST":
        username = request.form["username"]
        new_password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user:
            user.password = new_password
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
    app.run(host="0.0.0.0", port=5000, debug=True)