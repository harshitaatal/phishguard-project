from flask import Flask, request, render_template, redirect, url_for, session, flash, send_file, jsonify
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
from functools import wraps
from datetime import datetime
import os
import requests
import json
import whois
import re
import io
from fpdf import FPDF
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import func
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

# Load the primary XGBoost model
models = {}
model_info = {}

model_files = {
    'model_2_xgboost_classifier': {
        'key': 'model_2_xgboost_classifier',
        'file': r"pickle\model_2_xgboost_classifier.pkl",
        'name': 'XGBoost Classifier',
        'accuracy': 97.1,
        'description': 'Fast and efficient detection'
    }
}

# Load models
for model_id, info in model_files.items():
    try:
        with open(info['file'], "rb") as f:
            models[info['key']] = pickle.load(f)
            model_info[info['key']] = {
                'name': info['name'],
                'accuracy': info['accuracy'],
                'description': info['description']
            }
        print(f"OK: {info['name']} loaded successfully")
    except FileNotFoundError:
        print(f"Warning: {info['name']} not found at {info['file']}")
    except Exception as e:
        print(f"Error loading {info['name']}: {str(e)}")

print(f"\nTotal models loaded: {len(models)}")
print(f"Available model keys: {list(models.keys())}")

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login Manager Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    scans = db.relationship('ScanResult', backref='author', lazy=True)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    expanded_url = db.Column(db.String(500), nullable=True)
    safe_percentage = db.Column(db.Float, nullable=False)
    unsafe_percentage = db.Column(db.Float, nullable=False)
    is_safe = db.Column(db.Boolean, nullable=False)
    model_name = db.Column(db.String(100), nullable=False)
    creation_date = db.Column(db.String(100), nullable=True)
    domain_age = db.Column(db.String(100), nullable=True)
    feature_details = db.Column(db.Text, nullable=True)  # JSON string of feature analysis
    timestamp = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv', 'xlsx', 'xls'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Intelligence Utilities ---
def expand_url(url):
    """Expand shortened URLs to their final destination"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url if response.url != url else None
    except:
        return None

def get_domain_info(url):
    """Fetch WHOIS information for the domain"""
    try:
        domain = urlparse(url).netloc
        if not domain:
            domain = url.split('/')[0]
        
        # Clean domain (remove port if exists)
        if ':' in domain:
            domain = domain.split(':')[0]
            
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        # Handle cases where creation_date is a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # If creation_date is a string, try to parse it
            if isinstance(creation_date, str):
                from dateutil.parser import parse as date_parse
                try:
                    creation_date = date_parse(creation_date)
                except:
                    return "Unknown", "Unknown"

            # Ensure both are naive or both are aware. Stripping tzinfo is easier.
            now = datetime.now()
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            
            age_days = (now - creation_date).days
            years = age_days // 365
            months = (age_days % 365) // 30
            
            age_str = f"{years} years, {months} months" if years > 0 else f"{months} months"
            return creation_date.strftime('%Y-%m-%d'), age_str
    except Exception as e:
        print(f"WHOIS Error for {url}: {e}")
    return "Unknown", "Unknown"

# --- Feature Mapping for Explainability ---
FEATURE_NAMES = [
    "Using IP Address", "Long URL", "URL Shortener", "Symbol '@'", "Redirecting '//'",
    "Prefix/Suffix '-'", "Sub-domains", "HTTPS", "Domain Registration Length", "Favicon",
    "Non-Standard Port", "HTTPS in Domain", "Request URL (Media)", "Anchor URL", "Links in Script/Tags",
    "Server Form Handler", "Info Email", "Abnormal URL", "Website Forwarding", "Status Bar Cust.",
    "Disable Right Click", "Using Popup Window", "Iframe Redirection", "Age of Domain", "DNS Recording",
    "Website Traffic", "Page Rank", "Google Index", "Links Pointing to Page", "Stats Report"
]

FEATURE_DESCRIPTIONS = [
    "Checks if the URL contains an IP address instead of a domain name. Safe if no IP address is detected.",
    "Safe if length < 54 characters. Suspicious if 54-75 characters. Phishing if > 75 characters.",
    "Checks for common URL shortening services (like bit.ly). Phishing if a shortener is used.",
    "Checks for the '@' symbol. Phishing if present (used to hide the actual destination).",
    "Checks for '//' after the protocol. Phishing if present after the 6th position.",
    "Checks for hyphens '-' in the domain name. Phishing if present (rare in legitimate brands).",
    "Safe if 1 dot. Suspicious if 2 dots. Phishing if more than 2 dots in the domain.",
    "Checks if the URL uses the secure HTTPS protocol. Safe if HTTPS is detected.",
    "Checks domain registration length. Safe if the domain is registered for 1 year or more.",
    "Checks if the favicon is loaded from the same domain. Phishing if loaded from external domain.",
    "Checks for non-standard ports. Safe if using standard ports like 80 (HTTP) or 443 (HTTPS).",
    "Checks if 'https' is used as part of the domain string. Phishing if detected in domain.",
    "Safe if < 22% of media (img, video, etc.) is loaded from external domains.",
    "Safe if < 31% of anchor (links) point to external domains or use 'javascript' tags.",
    "Safe if < 17% of script and link tags point to external sources.",
    "Checks form actions. Phishing if action is empty, 'about:blank', or points to external domain.",
    "Checks for 'mailto:' in the page. Phishing if used to submit sensitive information.",
    "Checks if the domain is present in the page body. Phishing if not detected.",
    "Checks the number of redirects. Safe if there are 0 or 1 redirects detected.",
    "Checks for status bar manipulation via 'onmouseover' scripts. Phishing if detected.",
    "Checks for scripts that disable right-clicking. Phishing if detected.",
    "Checks for popup windows that ask for user input. Phishing if detected.",
    "Checks for the use of iframes. Phishing if detected (used to overlay malicious content).",
    "Checks the age of the domain. Safe if the domain is at least 6 months old.",
    "Checks if DNS records exist for the domain. Safe if records are found.",
    "Checks website traffic (Alexa rank). Safe if the rank is within the top 100,000 sites.",
    "Checks the PageRank of the website. Safe if the PageRank is greater than 0.",
    "Checks if the website is indexed by Google. Safe if indexed.",
    "Checks the number of links pointing to the page. Safe if more than 2 links are found.",
    "Checks against common phishing blacklists and stats reports. Phishing if matched."
]

def get_feature_analysis(features):
    """Map binary features to human readable analysis for the report"""
    analysis = []
    for i, val in enumerate(features):
        if i < len(FEATURE_NAMES):
            # 1: Safe, 0: Suspicious, -1: Phishing
            if val == 1:
                status = "Safe"
            elif val == 0:
                status = "Suspicious"
            else:
                status = "Phishing"
            
            analysis.append({
                "name": FEATURE_NAMES[i],
                "status": status,
                "description": FEATURE_DESCRIPTIONS[i],
                "value": int(val)
            })
    return analysis
# ----------------------------
# ----------------------------

# Database Initialization
with app.app_context():
    db.create_all()
    # Create default admin if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin')
        db.session.add(admin)
        db.session.commit()

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # Simple validation
        if not username or not password:
            flash('Username and Password are required', 'error')
            return redirect(url_for('register'))
            
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
            
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route("/bulk", methods=["GET", "POST"])
@login_required
def bulk_scan():
    if request.method == "POST":
        if 'dataset' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(request.url)
        
        file = request.files['dataset']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                if filename.endswith('.csv'):
                    df = pd.read_csv(filepath)
                else:
                    df = pd.read_excel(filepath)
                
                # Check for URL column
                url_col = next((col for col in df.columns if col.lower() in ['url', 'urls', 'link', 'links']), None)
                
                if not url_col:
                    flash(f'Error: Could not find a "url" column in {filename}. Please ensure your file has a column named "url".', 'error')
                    return redirect(request.url)

                # Use XGBoost as the engine for bulk scanning
                selected_model = 'model_2_xgboost_classifier'
                model = models.get(selected_model)
                
                if not model:
                    flash('Internal Error: XGBoost model not loaded.', 'error')
                    return redirect(request.url)

                results = []
                # Limit to first 20 URLs for performance reasons
                urls_to_scan = df[url_col].dropna().head(20).tolist()
                
                for url in urls_to_scan:
                    try:
                        # Basic validation
                        if not str(url).startswith(('http://', 'https://')):
                            full_url = "http://" + str(url)
                        else:
                            full_url = str(url)
                            
                        obj = FeatureExtraction(full_url)
                        features = obj.getFeaturesList()
                        x = np.array(features).reshape(1, 30)
                        
                        y_pred = model.predict(x)[0]
                        is_safe = y_pred == 1 or y_pred > 0
                        
                        # Store features for reasoning
                        analysis_data = get_feature_analysis(features)
                        
                        res = {
                            'url': url,
                            'is_safe': is_safe,
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'analysis': analysis_data
                        }
                        results.append(res)
                        
                        db_res = ScanResult(
                            url=url,
                            safe_percentage=100.0 if is_safe else 0.0,
                            unsafe_percentage=0.0 if is_safe else 100.0,
                            is_safe=is_safe,
                            model_name='XGBoost (Bulk)',
                            feature_details=json.dumps(analysis_data),
                            author=current_user
                        )
                        db.session.add(db_res)
                        db.session.flush() # Get the ID before commit
                        res['id'] = db_res.id
                    except Exception as e:
                        print(f"Error scanning bulk URL {url}: {e}")
                        results.append({'url': url, 'is_safe': 'Error', 'timestamp': 'N/A'})
                
                db.session.commit()
                scan_ids = [r.get('id') for r in results if r.get('id')]
                return render_template("upload.html", bulk_results=results, total=len(results), scan_ids=scan_ids)
                
            except Exception as e:
                flash(f'Error processing bulk scan: {str(e)}', 'error')
                return redirect(request.url)
        else:
            flash('Invalid file type. Please upload CSV or Excel files.', 'error')
            return redirect(request.url)
    
    return render_template("upload.html")

@app.route("/index", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        url = request.form["url"]
        selected_model = 'model_2_xgboost_classifier'
        
        # Check if the model is loaded
        if not models:
            flash('No models are currently loaded. Please check your model files.', 'error')
            latest_history = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).limit(5).all()
            return render_template('index.html', 
                                 history=latest_history, 
                                 models=model_info,
                                 available_models=list(models.keys()))
        
        # Validate selected model
        if selected_model not in models:
            flash(f'Model not available. Please check system configuration.', 'error')
            latest_history = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).limit(5).all()
            return render_template('index.html', history=latest_history, models=model_info)
        
        try:
            # --- New Intelligence Layer ---
            expanded = expand_url(url)
            effective_url = expanded if expanded else url
            creation_date, domain_age = get_domain_info(effective_url)
            # ------------------------------

            # Extract features from URL
            obj = FeatureExtraction(effective_url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            
            # Get the selected model
            model = models[selected_model]
            print(f"Using model: {selected_model}")
            
            # Make prediction
            y_pred = model.predict(x)[0]
            print(f"Prediction: {y_pred}")
            
            # Handle different prediction formats
            if hasattr(model, 'predict_proba'):
                y_proba = model.predict_proba(x)[0]
                if len(y_proba) == 2:
                    y_pro_phishing = y_proba[0]
                    y_pro_non_phishing = y_proba[1]
                else:
                    y_pro_phishing = 0.5
                    y_pro_non_phishing = 0.5
            else:
                if y_pred in [-1, 0]:
                    y_pro_phishing = 0.9
                    y_pro_non_phishing = 0.1
                else:
                    y_pro_phishing = 0.1
                    y_pro_non_phishing = 0.9
            
            # Determine final result
            is_safe = y_pred == 1 or y_pred > 0
            
            # Store in DB
            scan_result = ScanResult(
                url=url,
                expanded_url=expanded,
                safe_percentage=round(y_pro_non_phishing * 100, 2),
                unsafe_percentage=round(y_pro_phishing * 100, 2),
                is_safe=is_safe,
                model_name=model_info[selected_model]['name'],
                creation_date=creation_date,
                domain_age=domain_age,
                feature_details=json.dumps(get_feature_analysis(obj.getFeaturesList())),
                author=current_user
            )
            db.session.add(scan_result)
            db.session.commit()
            
            # Get latest history for display
            latest_history = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).limit(5).all()
            for item in latest_history:
                if item.feature_details:
                    try:
                        item.parsed_analysis = json.loads(item.feature_details)
                    except:
                        item.parsed_analysis = []
                else:
                    item.parsed_analysis = []
            
            print(f"Scan result saved to DB for user: {current_user.username}")
            
            return render_template('index.html', 
                                 result=scan_result,
                                 analysis=json.loads(scan_result.feature_details) if scan_result.feature_details else [],
                                 history=latest_history,
                                 models=model_info,
                                 available_models=list(models.keys()),
                                 selected_model=selected_model)
        except Exception as e:
            flash(f'Error analyzing URL: {str(e)}', 'error')
            print(f"Error details: {e}")  # For debugging
            import traceback
            traceback.print_exc()  # Print full traceback
            latest_history = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).limit(5).all()
            return render_template('index.html', 
                                 history=latest_history,
                                 models=model_info,
                                 available_models=list(models.keys()))
    
    # Default model selection for GET request
    default_model = list(models.keys())[0] if models else None
    latest_history = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).limit(5).all()
    # Parse feature details for display
    for item in latest_history:
        if item.feature_details:
            try:
                item.parsed_analysis = json.loads(item.feature_details)
            except:
                item.parsed_analysis = []
        else:
            item.parsed_analysis = []
    
    return render_template("index.html", 
                         history=latest_history,
                         models=model_info,
                         available_models=list(models.keys()),
                         selected_model=default_model)

@app.route("/history")
@login_required
def history():
    user_history = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).all()
    # Parse feature details for each history item
    for item in user_history:
        if item.feature_details:
            try:
                item.parsed_analysis = json.loads(item.feature_details)
            except:
                item.parsed_analysis = []
        else:
            item.parsed_analysis = []
    return render_template("history.html", history=user_history)

@app.route("/clear_history")
@login_required
def clear_history():
    ScanResult.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('Search history cleared.', 'success')
    return redirect(url_for('history'))

@app.route("/delete_scan/<int:id>")
@login_required
def delete_scan(id):
    scan = ScanResult.query.get_or_404(id)
    if scan.user_id != current_user.id:
        flash('Unauthorized action.', 'error')
        return redirect(url_for('index'))
    
    db.session.delete(scan)
    db.session.commit()
    flash('Scan result deleted.', 'success')
    return redirect(request.referrer or url_for('index'))


@app.route("/dashboard")
@login_required
def dashboard():
    # 1. Safe vs Phishing Stats
    stats = db.session.query(
        ScanResult.is_safe, 
        func.count(ScanResult.id)
    ).filter_by(user_id=current_user.id).group_by(ScanResult.is_safe).all()
    
    safe_count = 0
    phishing_count = 0
    for is_safe, count in stats:
        if is_safe:
            safe_count = count
        else:
            phishing_count = count

    # 2. Model Performance/Usage
    model_stats = db.session.query(
        ScanResult.model_name, 
        func.count(ScanResult.id)
    ).filter_by(user_id=current_user.id).group_by(ScanResult.model_name).all()
    
    model_labels = [s[0] for s in model_stats]
    model_data = [s[1] for s in model_stats]

    # 3. Scans over time (last 7 days)
    # Note: Using SQLite specific date formatting
    daily_stats = db.session.query(
        func.strftime('%Y-%m-%d', ScanResult.timestamp),
        func.count(ScanResult.id)
    ).filter_by(user_id=current_user.id).group_by(func.strftime('%Y-%m-%d', ScanResult.timestamp)).order_by(ScanResult.timestamp.desc()).limit(7).all()
    
    daily_labels = [s[0] for s in reversed(daily_stats)]
    daily_data = [s[1] for s in reversed(daily_stats)]

    # 4. Total stats
    total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
    
    return render_template("dashboard.html",
                         safe_count=safe_count,
                         phishing_count=phishing_count,
                         model_labels=model_labels,
                         model_data=model_data,
                         daily_labels=daily_labels,
                         daily_data=daily_data,
                         total_scans=total_scans)

@app.route("/email_scanner", methods=["GET", "POST"])
@login_required
def email_scanner():
    if request.method == "POST":
        content = request.form.get("content", "")
        
        # Regex to find URLs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        urls = re.findall(url_pattern, content)
        
        # Remove duplicates
        urls = list(set(urls))
        
        if not urls:
            flash('No URLs found in the provided content.', 'info')
            return render_template("email_scanner.html", content=content)

        results = []
        selected_model = 'model_2_xgboost_classifier'
        model = models.get(selected_model)
        
        for url in urls:
            try:
                obj = FeatureExtraction(url)
                features = obj.getFeaturesList()
                x = np.array(features).reshape(1, 30)
                y_pred = model.predict(x)[0]
                is_safe = y_pred == 1 or y_pred > 0
                
                results.append({
                    'url': url,
                    'is_safe': is_safe,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                
                # Save to history for PDF report capability
                db_res = ScanResult(
                    url=url,
                    safe_percentage=100.0 if is_safe else 0.0,
                    unsafe_percentage=0.0 if is_safe else 100.0,
                    is_safe=is_safe,
                    model_name='XGBoost (Email Scan)',
                    author=current_user
                )
                db.session.add(db_res)
                db.session.flush()
                results[-1]['id'] = db_res.id
            except Exception as e:
                print(f"Error scanning email URL {url}: {e}")
        
        db.session.commit()
        scan_ids = [r.get('id') for r in results if r.get('id')]
        return render_template("email_scanner.html", results=results, content=content, scan_ids=scan_ids)
        
    return render_template("email_scanner.html")

@app.route("/download_report/<int:scan_id>")
@login_required
def download_report(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('history'))

    # Create PDF
    pdf = FPDF()
    pdf.add_page()
    
    # Header
    pdf.set_fill_color(10, 10, 31)  # Dark theme background
    pdf.rect(0, 0, 210, 40, 'F')
    
    pdf.set_font("Arial", 'B', 24)
    pdf.set_text_color(0, 245, 255)  # Cyan
    pdf.cell(0, 20, "PhishGuard Intelligence Report", 0, 1, 'C')
    
    # Scan Info
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", 'B', 12)
    pdf.ln(20)
    
    pdf.cell(0, 10, f"Analysis Date: {scan.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.cell(0, 10, f"Target URL: {scan.url}", 0, 1)
    pdf.cell(0, 10, f"Detection Model: {scan.model_name}", 0, 1)
    
    pdf.ln(10)
    
    # Result Box
    status = "SAFE" if scan.is_safe else "MALICIOUS / PHISHING"
    color = (48, 209, 88) if scan.is_safe else (255, 69, 58)
    
    pdf.set_fill_color(*color)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 15, f"VERDICT: {status}", 0, 1, 'C', True)
    
    pdf.ln(10)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", '', 12)
    pdf.multi_cell(0, 10, f"The analysis of this URL has yielded a security score of {scan.safe_percentage}% safety confidence.")
    
    if not scan.is_safe:
        pdf.set_text_color(255, 0, 0)
        pdf.set_font("Arial", 'B', 12)
        pdf.ln(5)
        pdf.multi_cell(0, 10, "WARNING: This URL exhibits patterns consistent with phishing attacks. Accessing this site may result in identity theft or financial loss.")
    
    pdf.set_text_color(100, 100, 100)
    pdf.set_font("Arial", 'I', 10)
    pdf.ln(20)
    pdf.cell(0, 10, "This report was generated by the PhishGuard AI engine.", 0, 1, 'C')

    # --- New Detailed Features Page ---
    pdf.add_page()
    
    # Header for second page
    pdf.set_fill_color(10, 10, 31)
    pdf.rect(0, 0, 210, 30, 'F')
    pdf.set_font("Arial", 'B', 16)
    pdf.set_text_color(0, 245, 255)
    pdf.cell(0, 15, "Security Analysis: Feature Breakdown & Logic", 0, 1, 'C')
    
    pdf.ln(10)
    pdf.set_text_color(0, 0, 0)
    
    # Get features from scan record
    try:
        features_list = json.loads(scan.feature_details) if scan.feature_details else []
    except:
        features_list = []
        
    if features_list:
        for i, f in enumerate(features_list):
            # Check if we need a new page (roughly 6 features per page with descriptions)
            if i > 0 and i % 7 == 0:
                pdf.add_page()
                pdf.set_fill_color(10, 10, 31)
                pdf.rect(0, 0, 210, 20, 'F')
                pdf.ln(20)

            # Feature Name and Status
            pdf.set_font("Arial", 'B', 11)
            pdf.set_text_color(10, 10, 31)
            pdf.cell(150, 8, f"{i+1}. {f['name']}", 0, 0)
            
            # Color coding for status
            if f['status'] == "Safe":
                pdf.set_text_color(48, 209, 88)
            elif f['status'] == "Suspicious":
                pdf.set_text_color(255, 159, 10)
            else:
                pdf.set_text_color(255, 69, 58)
            
            pdf.cell(40, 8, f.get('status', 'Unknown').upper(), 0, 1, 'R')
            
            # Description / Logic
            pdf.set_font("Arial", '', 10)
            pdf.set_text_color(60, 60, 60)
            description = f.get('description', 'No explanation available.')
            pdf.multi_cell(0, 6, f"Security Logic: {description}")
            
            # Divider line
            pdf.set_draw_color(230, 230, 230)
            pdf.line(10, pdf.get_y() + 2, 200, pdf.get_y() + 2)
            pdf.ln(5)
    else:
        pdf.set_font("Arial", 'I', 10)
        pdf.cell(0, 10, "Detailed feature breakdown is not available for this record.", 0, 1, 'C')

    # Output to buffer
    output = io.BytesIO()
    pdf_bytes = pdf.output()
    output.write(pdf_bytes)
    output.seek(0)
    
    return send_file(
        output,
        as_attachment=True,
        download_name=f"PhishGuard_Report_{scan_id}.pdf",
        mimetype='application/pdf'
    )

@app.route("/download_batch_report")
@login_required
def download_batch_report():
    ids_str = request.args.get("ids", "")
    if not ids_str:
        flash("No scans selected for report.", "error")
        return redirect(url_for('bulk_scan'))
    
    try:
        scan_ids = [int(id_str) for id_str in ids_str.split(",") if id_str.strip()]
        scans = ScanResult.query.filter(ScanResult.id.in_(scan_ids), ScanResult.user_id == current_user.id).all()
        
        if not scans:
            flash("No valid scans found for the report.", "error")
            return redirect(url_for('bulk_scan'))

        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_fill_color(10, 10, 31)  # Dark theme background
        pdf.rect(0, 0, 210, 40, 'F')
        
        pdf.set_font("Arial", 'B', 22)
        pdf.set_text_color(0, 245, 255)  # Cyan
        pdf.cell(0, 20, "PhishGuard Batch Intelligence Report", 0, 1, 'C')
        
        pdf.set_font("Arial", '', 10)
        pdf.set_text_color(200, 200, 200)
        pdf.cell(0, 5, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        
        pdf.set_text_color(0, 0, 0)
        pdf.ln(25)
        
        # Summary Stats
        total = len(scans)
        safe = len([s for s in scans if s.is_safe])
        malicious = total - safe
        
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "Batch Summary Statistics", 0, 1)
        pdf.set_font("Arial", '', 12)
        pdf.cell(60, 10, f"Total URLs Scanned: {total}", 0, 0)
        pdf.set_text_color(48, 209, 88)
        pdf.cell(60, 10, f"Safe: {safe}", 0, 0)
        pdf.set_text_color(255, 69, 58)
        pdf.cell(60, 10, f"Malicious: {malicious}", 0, 1)
        
        pdf.ln(10)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "Detailed Intelligence Findings", 0, 1)
        
        # Table Header
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(100, 10, "Target URL", 1, 0, 'C', True)
        pdf.cell(40, 10, "Security Verdict", 1, 0, 'C', True)
        pdf.cell(50, 10, "Detection Engine", 1, 1, 'C', True)
        
        # Table Rows
        pdf.set_font("Arial", '', 9)
        for scan in scans:
            # Handle long URLs by truncation for the table
            display_url = scan.url
            if len(display_url) > 55:
                display_url = display_url[:52] + "..."
                
            pdf.cell(100, 10, display_url, 1)
            
            # Status with color coding (simulated in text)
            status = "SAFE" if scan.is_safe else "MALICIOUS"
            if not scan.is_safe:
                pdf.set_text_color(255, 0, 0)
            else:
                pdf.set_text_color(0, 150, 0)
            
            pdf.cell(40, 10, status, 1, 0, 'C')
            pdf.set_text_color(0, 0, 0)
            pdf.cell(50, 10, scan.model_name, 1, 1, 'C')
            
        pdf.ln(20)
        pdf.set_font("Arial", 'I', 10)
        pdf.set_text_color(100, 100, 100)
        pdf.multi_cell(0, 10, "Disclaimer: This report is generated based on architectural feature analysis and machine learning predictions. Always exercise caution when visiting unknown links.", 0, 'C')

        # Output to buffer
        output = io.BytesIO()
        pdf_bytes = pdf.output()
        output.write(pdf_bytes)
        output.seek(0)
        
        return send_file(
            output,
            as_attachment=True,
            download_name=f"PhishGuard_Batch_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        flash(f"Error generating batch report: {str(e)}", "error")
        return redirect(url_for('bulk_scan'))

@app.route("/api/scan", methods=["POST", "OPTIONS"])
def api_scan():
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST")
        return response

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400
    
    url = data['url']
    selected_model = 'model_2_xgboost_classifier'
    
    if not models or selected_model not in models:
        return jsonify({"error": "Model not loaded"}), 500
        
    try:
        expanded = expand_url(url)
        effective_url = expanded if expanded else url
        creation_date, domain_age = get_domain_info(effective_url)
        
        obj = FeatureExtraction(effective_url)
        features = obj.getFeaturesList()
        x = np.array(features).reshape(1, 30)
        
        model = models[selected_model]
        y_pred = model.predict(x)[0]
        
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(x)[0]
            if len(y_proba) == 2:
                y_pro_phishing = float(y_proba[0])
                y_pro_non_phishing = float(y_proba[1])
            else:
                y_pro_phishing = 0.5
                y_pro_non_phishing = 0.5
        else:
            y_pro_phishing = 0.9 if y_pred in [-1, 0] else 0.1
            y_pro_non_phishing = 0.1 if y_pred in [-1, 0] else 0.9
            
        is_safe = bool(y_pred == 1 or y_pred > 0)
        
        result = {
            "url": url,
            "is_safe": is_safe,
            "safe_percentage": round(y_pro_non_phishing * 100, 2),
            "unsafe_percentage": round(y_pro_phishing * 100, 2),
            "domain_age": domain_age,
            "model_used": model_info[selected_model]['name']
        }
        
        response = jsonify(result)
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response
    except Exception as e:
        response = jsonify({"error": str(e)})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500

if __name__ == "__main__":
    app.run(debug=True)