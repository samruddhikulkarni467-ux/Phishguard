# PhishGuard — WhatsApp Fraud Link Detector

## About
PhishGuard is a Chrome extension prototype that identifies potentially suspicious links on WhatsApp Web using rule-based URL analysis.

## Features
- Scans links displayed on WhatsApp Web.
- Assigns risk scores using configurable URL characteristics.
- Displays warnings for links that meet configured risk thresholds.
- Shows reasons for suspicious URL patterns.
- Uses a heuristic approach to flag potentially risky links.

## Technologies Used
- JavaScript
- HTML
- CSS
- Chrome Extension Manifest V3

## Installation
1. Clone or download this repository.
2. Open Google Chrome and visit `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the PhishGuard project folder.
6. Open WhatsApp Web and test the extension.

## How It Works
PhishGuard checks URL characteristics such as suspicious domain patterns, certain top-level domains, URL shorteners, and other configured indicators. It calculates a risk score and displays a warning when the score reaches the configured threshold.

## Limitations
PhishGuard is a prototype, not a definitive phishing detector. Its heuristic rules can produce false positives and may miss malicious URLs. A URL that is not flagged is not necessarily safe.

## Future Improvements
- Add automated tests for URL analysis.
- Evaluate detection using a labeled dataset.
- Measure precision, recall, and false-positive rates.
- Improve scoring rules and detection coverage.

## Repository
[View PhishGuard on GitHub](https://github.com/samruddhikulkarni467-ux/Phishguard)
