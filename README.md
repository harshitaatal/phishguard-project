# PhishGuard: Phishing URL Detection System

PhishGuard is a comprehensive security solution designed to protect users from phishing attacks. It utilizes machine learning (XGBoost) and advanced feature extraction to analyze URLs in real-time and determine their legitimacy.

## 🚀 Features

- **Real-time URL Analysis**: Scans URLs for suspicious patterns and technical indicators.
- **Machine Learning Powered**: Uses an XGBoost model trained on thousands of phishing and legitimate URLs.
- **Chrome Extension**: A dedicated browser extension for seamless protection while browsing.
- **Flask Web Application**: A user-friendly dashboard to manually check URLs and generate security reports.
- **Detailed Security Reports**: Generates PDF reports with a breakdown of various security features (WHOIS data, HTTPS status, URL length, etc.).
- **Educational Insights**: Provides clear rationales for why a URL is classified as suspicious or safe.

## 🛠️ Tech Stack

- **Backend**: Python, Flask, SQLAlchemy
- **Machine Learning**: XGBoost, Scikit-learn, Pandas, NumPy
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Database**: SQLite
- **Extension**: Chrome Extension Manifest V3
- **Reporting**: ReportLab (PDF Generation)

## 📁 Project Structure

```text
├── Phishing-URL-Detection/   # Flask Backend Application
│   ├── app.py                # Main Flask entry point
│   ├── feature.py            # URL feature extraction engine
│   ├── templates/            # HTML templates
│   ├── static/               # CSS and JS assets
│   └── requirements.txt      # Python dependencies
├── chrome-extension/         # Browser Extension
│   ├── manifest.json         # Extension configuration
│   ├── background.js         # Background script
│   └── popup.html            # Extension popup UI
└── .gitignore                # Git exclusion rules
```

## ⚙️ Installation & Setup

### Backend (Flask)

1. Navigate to the backend directory:
   ```bash
   cd Phishing-URL-Detection
   ```
2. Create a virtual environment:
   ```bash
   python -m venv venv
   ```
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/macOS: `source venv/bin/activate`
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Run the application:
   ```bash
   python app.py
   ```

### Chrome Extension

1. Open Chrome and go to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked**.
4. Select the `chrome-extension` folder from this project.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
