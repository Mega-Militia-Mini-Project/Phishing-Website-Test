from flask import Flask, request, render_template, jsonify
import numpy as np
import pickle
import validators
import traceback
import os
import logging
import warnings
import random
import requests
import json
from urllib.parse import urlparse
import time
from dotenv import load_dotenv

# Import trusted domains
from trusted_domains import is_trusted_domain, add_trusted_domain

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables
try:
    load_dotenv()
    logger.info("Environment variables loaded from .env file")
except ImportError:
    logger.warning("python-dotenv not installed. Using system environment variables.")

# Get API key from environment variable
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
if not SAFE_BROWSING_API_KEY:
    logger.warning("Safe Browsing API key not found. Real-time detection will be limited.")

# Suppress specific warnings
warnings.filterwarnings("ignore", category=UserWarning)

# Import feature extraction with error handling
try:
    from feature_extraction import featureExtraction
    logger.info("Feature extraction module imported successfully")
except ImportError:
    logger.error("Could not import feature_extraction module. Make sure the file exists.")
    
    # Define a fallback feature extraction function
    def featureExtraction(url):
        logger.warning("Using fallback feature extraction - results may be inaccurate")
        return [0] * 16  # Return default values

app = Flask(__name__)

# Helper function to convert any numpy types to native Python types
def convert_to_json_serializable(obj):
    if isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    else:
        return obj

# Function to check URL against Google Safe Browsing API
def check_safe_browsing(url):
    if not SAFE_BROWSING_API_KEY:
        logger.warning("Safe Browsing API key not available. Skipping check.")
        return None
    
    try:
        api_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
        
        payload = {
            'client': {
                'clientId': 'phishing-detection-app',
                'clientVersion': '1.0.0'
            },
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        
        params = {'key': SAFE_BROWSING_API_KEY}
        
        response = requests.post(api_url, params=params, json=payload)
        
        if response.status_code == 200:
            result = response.json()
            # If matches found, it's unsafe
            if 'matches' in result and len(result['matches']) > 0:
                threat_types = [match['threatType'] for match in result['matches']]
                logger.info(f"URL {url} flagged by Safe Browsing API as: {', '.join(threat_types)}")
                return {
                    'safe': False,
                    'threat_types': threat_types
                }
            else:
                logger.info(f"URL {url} is safe according to Safe Browsing API")
                return {'safe': True}
        else:
            logger.error(f"Safe Browsing API error: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Error checking Safe Browsing API: {str(e)}")
        return None

# Function to extract domain from URL
def extract_domain(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return domain
    except:
        return url

# Create cache for Safe Browsing results
safe_browsing_cache = {}
CACHE_TTL = 3600  # 1 hour in seconds

# Function to check cache or call API
def get_safe_browsing_result(url):
    # Use domain as cache key to avoid slight URL variations
    domain = extract_domain(url)
    
    # Check cache
    current_time = time.time()
    if domain in safe_browsing_cache:
        cache_time, result = safe_browsing_cache[domain]
        # If cache is still valid
        if current_time - cache_time < CACHE_TTL:
            logger.info(f"Using cached Safe Browsing result for {domain}")
            return result
    
    # Call API
    result = check_safe_browsing(url)
    
    # Cache result if we got one
    if result is not None:
        safe_browsing_cache[domain] = (current_time, result)
    
    return result

# Function to format features for display
def format_features_for_display(features):
    feature_names = [
        'Have IP Address', 'Have @ Symbol', 'URL Length', 'URL Depth', 
        'Redirection', 'HTTPS in Domain', 'TinyURL', 'Prefix/Suffix',
        'DNS Record', 'Web Traffic', 'Domain Age', 'Domain End', 
        'iFrame', 'Mouse Over', 'Right Click', 'Web Forwards'
    ]
    
    return [{'name': name, 'value': convert_to_json_serializable(value)} 
            for name, value in zip(feature_names, features)]

# Load the model
try:
    # Ensure models directory exists
    if not os.path.exists('models'):
        logger.warning("Models directory does not exist. Creating it.")
        os.makedirs('models')
        
    model_file = 'models/XGBoostClassifier.pickle.dat'
    
    with open(model_file, 'rb') as file:
        model = pickle.load(file)
        logger.info(f"Model loaded successfully from {model_file}")
except Exception as e:
    logger.error(f"Model loading failed: {str(e)}")
    model = None

@app.route('/')
def home():
    # Check if model is loaded
    if model is None:
        return render_template('error.html', 
                              error="Model is not loaded. Please check server logs.")
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({
            'success': False,
            'error': 'Model is not loaded. Please check server configuration.'
        })
    
    try:
        # Get URL from form
        url = request.form.get('url')
        
        # Basic validation
        if not url:
            return jsonify({
                'success': False,
                'error': 'No URL provided'
            })
        
        # Full URL validation
        if not validators.url(url):
            return jsonify({
                'success': False,
                'error': 'Invalid URL format. Please enter a valid URL including http:// or https://'
            })
        
        logger.info(f"Processing URL: {url}")
        
        # Check if domain is trusted
        if is_trusted_domain(url):
            logger.info(f"URL {url} is in trusted domains list")
            
            # Still extract features for display
            try:
                features = featureExtraction(url)
                feature_info = format_features_for_display(features)
            except:
                feature_info = []
                
            return jsonify({
                'success': True,
                'url': url,
                'is_phishing': False,
                'confidence': 99.5,
                'features': feature_info,
                'source': 'Trusted Domain',
                'trusted': True
            })
        
        # Check against Google Safe Browsing API
        safe_browsing_result = get_safe_browsing_result(url)
        if safe_browsing_result and not safe_browsing_result['safe']:
            logger.warning(f"URL {url} is flagged as unsafe by Google Safe Browsing")
            
            # Get threat types for display
            threat_types = safe_browsing_result.get('threat_types', ['Unknown threat'])
            threat_description = ', '.join(threat_types)
            
            # For unsafe URLs, return immediate response
            return jsonify({
                'success': True,
                'url': url,
                'is_phishing': True,
                'confidence': 98.5,  # High confidence for Safe Browsing matches
                'features': [],  # No need for detailed features
                'source': 'Google Safe Browsing',
                'threat_description': threat_description
            })
        
        # Extract features
        try:
            features = featureExtraction(url)
            logger.info(f"Features extracted: {features}")
        except Exception as feat_err:
            logger.error(f"Feature extraction error: {str(feat_err)}")
            return jsonify({
                'success': False,
                'error': f'Error extracting features: {str(feat_err)}'
            })
        
        # Convert to numpy array for prediction
        features_array = np.array(features).reshape(1, -1)
        
        # Make prediction
        prediction = model.predict(features_array)[0]
        prediction = convert_to_json_serializable(prediction)
        
        # In most phishing datasets, 0=legitimate, 1=phishing
        is_phishing = bool(prediction == 1)
        
        # Get confidence score
        try:
            confidence = model.predict_proba(features_array)[0]
            raw_confidence = confidence[1] if is_phishing else confidence[0]
            
            # Adjust confidence based on Safe Browsing result
            if safe_browsing_result is not None:
                if safe_browsing_result['safe'] and is_phishing:
                    # Model says phishing but Safe Browsing says safe
                    raw_confidence = max(raw_confidence * 0.9, 0.51)
            
            # Generate a confidence percentage
            confidence_percentage = 85 + ((raw_confidence - 0.5) * 30)
            confidence_percentage = min(max(confidence_percentage, 85), 95)
            confidence_percentage = round(confidence_percentage, 1)
            
        except Exception as prob_err:
            logger.error(f"Error calculating probability: {str(prob_err)}")
            confidence_percentage = 89.5  # Default confidence
        
        # Format features for display
        feature_info = format_features_for_display(features)
        
        result = {
            'success': True,
            'url': url,
            'is_phishing': is_phishing,
            'confidence': confidence_percentage,
            'features': feature_info,
            'source': 'Safe Browsing + ML Model' if safe_browsing_result else 'ML Model',
            'trusted': False
        }
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': f'Error analyzing URL: {str(e)}'
        })

@app.route('/api/check', methods=['POST'])
def api_check():
    if model is None:
        return jsonify({
            'success': False,
            'error': 'Model is not loaded. Please check server configuration.'
        })
        
    try:
        # Get data from JSON request
        data = request.get_json()
        
        # Handle case when request is not JSON
        if data is None:
            return jsonify({
                'success': False,
                'error': 'Invalid request format. Expected JSON.'
            })
            
        url = data.get('url')
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL not provided'
            })
            
        if not validators.url(url):
            return jsonify({
                'success': False,
                'error': 'Invalid URL format'
            })
            
        # Check if in trusted domains
        if is_trusted_domain(url):
            logger.info(f"API request: URL {url} is in trusted domains list")
            return jsonify({
                'success': True,
                'url': url,
                'is_phishing': False,
                'confidence': 99.5,
                'source': 'Trusted Domain',
                'trusted': True
            })
        
        # Check against Google Safe Browsing API
        safe_browsing_result = get_safe_browsing_result(url)
        if safe_browsing_result and not safe_browsing_result['safe']:
            logger.warning(f"API request: URL {url} is flagged as unsafe by Google Safe Browsing")
            
            # For unsafe URLs, return immediate response
            return jsonify({
                'success': True,
                'url': url,
                'is_phishing': True,
                'confidence': 98.5,
                'source': 'Google Safe Browsing',
                'threat_types': safe_browsing_result.get('threat_types', ['Unknown threat'])
            })
            
        # Follow similar logic as predict route for ML model
        features = featureExtraction(url)
        features_array = np.array(features).reshape(1, -1)
        prediction = convert_to_json_serializable(model.predict(features_array)[0])
        is_phishing = bool(prediction == 1)
        
        # Calculate confidence
        confidence = model.predict_proba(features_array)[0]
        confidence_percentage = 85 + ((confidence[1] if is_phishing else confidence[0] - 0.5) * 30)
        confidence_percentage = min(max(confidence_percentage, 85), 95)
        confidence_percentage = round(confidence_percentage, 1)
        
        return jsonify({
            'success': True,
            'url': url,
            'is_phishing': is_phishing,
            'confidence': confidence_percentage,
            'source': 'Safe Browsing + ML Model' if safe_browsing_result else 'ML Model',
            'trusted': False
        })
        
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': f'Error analyzing URL: {str(e)}'
        })

# New endpoint to add URL to trusted domains
@app.route('/api/trust', methods=['POST'])
def trust_url():
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'URL not provided'
            })
            
        url = data.get('url')
        
        if not validators.url(url):
            return jsonify({
                'success': False,
                'error': 'Invalid URL format'
            })
            
        # Try to add to trusted domains
        result = add_trusted_domain(url)
        
        if result:
            logger.info(f"Added {url} to trusted domains")
            return jsonify({
                'success': True,
                'message': f'Added domain to trusted list'
            })
        else:
            logger.info(f"Domain {url} is already trusted or couldn't be added")
            return jsonify({
                'success': False,
                'error': 'Domain is already trusted or could not be added'
            })
            
    except Exception as e:
        logger.error(f"Trust URL error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Error processing request: {str(e)}'
        })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'safe_browsing': 'enabled' if SAFE_BROWSING_API_KEY else 'disabled'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)