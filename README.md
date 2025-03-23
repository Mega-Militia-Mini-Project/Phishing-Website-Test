# Phishing Website Detection using Machine Learning

## Overview
Phishing websites pose a significant security risk, tricking users into divulging sensitive information. This project leverages machine learning techniques to classify URLs as either **legitimate** or **phishing**, based on extracted features.

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
  - MultiLayer Perceptron
  - XGBoost
  - Support Vector Machines
- Preliminary results indicate **promising accuracy**, with further optimizations underway.

## Current Status
- Feature extraction has been implemented and validated with an improved approach that correctly handles known legitimate domains.
- Our XGBoost classifier achieves high accuracy in distinguishing between legitimate and phishing URLs.
- The system now includes detailed feature explanations to help users understand why a URL was classified as phishing.

## Next Steps
- Fine-tuning model performance and improving dataset updates.
- Exploring integration with real-time phishing data sources.
- Evaluating potential deployment strategies (browser extension, API, etc.).

This is an ongoing project, and further insights will be shared in subsequent updates.
