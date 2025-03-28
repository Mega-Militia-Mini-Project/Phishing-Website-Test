# Phishing Website Detection using Machine Learning

## Overview
Phishing websites pose a significant security risk, tricking users into divulging sensitive information. This project leverages machine learning techniques to classify URLs as either **legitimate** or **phishing**, based on extracted features. The system is implemented as a web application with a user-friendly interface for URL classification and analysis.

## Quick Start Guide

### Prerequisites
- Python 3.7 or higher
- Git
- pip (Python package installer)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/Phishing-Website-Test.git
   cd Phishing-Website-Test
   ```

2. Create and activate a virtual environment (optional but recommended):
   ```bash
   # On Windows
   python -m venv venv
   venv\Scripts\activate

   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:
   ```bash
   python app.py
   ```

5. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

### Using the API
The project provides RESTful API endpoints for programmatic access:

1. Check if a URL is phishing:
   ```bash
   curl -X POST http://localhost:5000/api/check \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
   ```

2. Add a URL to trusted domains:
   ```bash
   curl -X POST http://localhost:5000/api/trust \
     -H "Content-Type: application/json" \
     -d '{"url": "https://trusteddomain.com", "key": "your_admin_key"}'
   ```

## Project Structure
```
Phishing-Website-Test/
├── app.py                      # Flask application entry point
├── models/                     # Trained machine learning models
│   └── XGBoostClassifier.pickle.dat # Main model used for predictions
├── data/                       # Training and validation datasets
├── notebooks/                  # Jupyter notebooks for analysis and model training
├── templates/                  # HTML templates for the web interface
├── static/                     # CSS, JavaScript, and image files
├── URLFeatureExtraction_fixed.py # Feature extraction module
└── requirements.txt            # Python dependencies
```

## Data Collection
- **Legitimate URLs** sourced from the University of New Brunswick dataset: [UNB Dataset](https://www.unb.ca/cic/datasets/url-2016.html).
- **Phishing URLs** obtained from PhishTank, a real-time phishing database: [PhishTank API](https://www.phishtank.com/developer_info.php).
- The dataset comprises a balanced selection of legitimate and phishing URLs for model training.

## Feature Extraction
- Extracted **essential URL-based features**, including:
  - Address bar characteristics (e.g., presence of "@").
  - Domain-level information (e.g., domain age, DNS records).
  - Webpage behavior indicators (e.g., iframe usage, redirections).
- Features are extracted by our `URLFeatureExtraction_fixed.py` module
- Known trusted domains like Google and Microsoft are automatically classified as safe

## Machine Learning Approach
- The dataset is split into **training (80%) and testing (20%)**.
- Multiple classification models are evaluated, including:
  - Decision Tree
  - Random Forest
  - MultiLayer Perceptron (MLP)
  - XGBoost
  - Support Vector Machines (SVM)
  - Autoencoder Neural Network
- XGBoost classifier showed the best performance and is currently used as the primary model.

## Web Application
- Built with Flask, offering both UI and API endpoints
- Features a responsive interface for real-time URL analysis
- Provides detailed feature-based explanations for detection results
- Endpoints include:
  - `/predict` - Analyzes URLs submitted through the web interface
  - `/api/check` - RESTful API endpoint for URL checking
  - `/api/trust` - API endpoint to add URLs to trusted domains list
  - `/health` - Health check endpoint for monitoring

## Advanced Detection Features
- **Critical phishing indicators** detection that immediately flags dangerous URLs
- **Trusted domains system** that automatically classifies known legitimate websites
- **Google Safe Browsing API** integration to verify URLs against known threats
- **Detailed feature breakdown** showing which URL characteristics contributed to classification
- **Trust management system** allowing administrators to mark domains as trusted

## Current Status
- Feature extraction has been implemented and validated with an improved approach that correctly handles known legitimate domains.
- Our XGBoost classifier achieves high accuracy in distinguishing between legitimate and phishing URLs.
- The system provides detailed threat information when malicious URLs are detected via Google Safe Browsing.
- A working web application has been deployed with both UI and API access points.

## Configuration
### Required Environment Variables
- `PORT`: Port for the web application (default: 5000)
- `ADMIN_KEY`: Secret key for adding trusted domains (default: none)
- `GOOGLE_SAFE_BROWSING_API_KEY`: Optional key for Google Safe Browsing integration

### Custom Model Integration
If you want to use your own trained model:
1. Save your model in the `models/` directory
2. Update the model file path in `app.py`

## Troubleshooting
- **Missing dependencies**: Make sure all requirements are installed
- **Model loading error**: Ensure the model file exists in the specified path
- **Feature extraction issues**: Check if website is accessible and not blocking automated access

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Next Steps
- Fine-tuning model performance and improving dataset updates.
- Exploring integration with additional real-time phishing data sources.
- Enhancing the machine learning pipeline with automated retraining capabilities.
- Evaluating potential deployment strategies (browser extension, API service, etc.).
- Implementing user feedback collection to further improve detection accuracy.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

---

This is an actively maintained project with ongoing improvements to detection accuracy and user experience.
