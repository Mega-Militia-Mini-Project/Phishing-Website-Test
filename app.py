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
import threading
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
        return [0] * 16  # Return default features for 16 features

app = Flask(__name__)

# Cache for feature extraction and Safe Browsing results
feature_extraction_cache = {}
safe_browsing_cache = {}
CACHE_TTL = 3600  # 1 hour in seconds

# Custom JSON encoder for NumPy types
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer, np.int64, np.int32, np.int8, np.uint8)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        return super(NumpyEncoder, self).default(obj)

# Configure Flask to use the custom encoder
app.json_encoder = NumpyEncoder

# Helper function to convert any numpy types to native Python types
def convert_to_json_serializable(obj):
    if isinstance(obj, (np.integer, np.int64, np.int32, np.int8, np.uint8)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, np.bool_):
        return bool(obj)
    else:
        return obj

# Function to check URL against Google Safe Browsing API with timeout and retries
def check_safe_browsing(url, timeout=5, max_retries=2):
    if not SAFE_BROWSING_API_KEY:
        logger.warning("Safe Browsing API key not available. Skipping check.")
        return None
    
    for attempt in range(max_retries + 1):
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
            
            response = requests.post(api_url, params=params, json=payload, timeout=timeout)
            
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
                # Only retry on server errors (5xx)
                if response.status_code < 500:
                    return None
        except requests.exceptions.Timeout:
            logger.warning(f"Safe Browsing API timeout (attempt {attempt+1}/{max_retries+1})")
        except requests.exceptions.RequestException as e:
            logger.error(f"Safe Browsing API request error: {str(e)}")
        except Exception as e:
            logger.error(f"Error checking Safe Browsing API: {str(e)}")
            return None
            
        # If we need to retry, wait with exponential backoff
        if attempt < max_retries:
            wait_time = (2 ** attempt) * 0.5  # 0.5, 1, 2 seconds...
            logger.info(f"Retrying Safe Browsing API check in {wait_time} seconds")
            time.sleep(wait_time)
            
    return None

# Function to extract domain from URL more robustly
def extract_domain(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove port number if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        # Remove 'www.' prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {str(e)}")
        return url

# Function to check cache or call API with expiration handling
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

# Improved feature extraction with caching and error handling
def extract_features_safely(url, use_cache=True):
    # Use domain as cache key
    domain = extract_domain(url)
    cache_key = f"{domain}_{url[:50]}"  # Use domain + first 50 chars of URL as key
    
    # Check cache first if enabled
    current_time = time.time()
    if use_cache and cache_key in feature_extraction_cache:
        cache_time, features = feature_extraction_cache[cache_key]
        if current_time - cache_time < CACHE_TTL:
            logger.info(f"Using cached features for {domain}")
            return features
    
    # Extract features with timeout handling
    try:
        # Use a separate thread with timeout
        features_result = [None]
        extraction_error = [None]
        
        def extract_thread():
            try:
                features_result[0] = featureExtraction(url)
            except Exception as e:
                extraction_error[0] = str(e)
        
        # Run extraction in a thread with timeout
        thread = threading.Thread(target=extract_thread)
        thread.daemon = True
        thread.start()
        thread.join(timeout=15)  # 15 second timeout
        
        if thread.is_alive():
            logger.warning(f"Feature extraction timeout for {url}")
            return None
            
        if extraction_error[0]:
            logger.error(f"Feature extraction error: {extraction_error[0]}")
            return None
            
        features = features_result[0]
        
        # Validate features
        if features is None:
            logger.error(f"Feature extraction returned None for {url}")
            return None
            
        if len(features) != 16:
            logger.warning(f"Unexpected feature count: got {len(features)}, expected 16 for {url}")
            # Try to pad or truncate if needed
            if len(features) < 16:
                features = features + [0] * (16 - len(features))
            else:
                features = features[:16]
                
        # Cache the result
        if use_cache:
            feature_extraction_cache[cache_key] = (current_time, features)
            
        return features
        
    except Exception as e:
        logger.error(f"Error in feature extraction for {url}: {str(e)}")
        return None

# Function to get predefined safe features for trusted domains
def get_safe_features():
    """Return predefined 'safe' feature values for trusted domains"""
    # Features that indicate safety when 0
    safe_features_zero = [0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0]
    
    # These features correspond to:
    # [Have IP Address, Have @ Symbol, URL Length, URL Depth, Redirection, HTTPS in Domain,
    #  TinyURL, Prefix/Suffix, DNS Record, Web Traffic, Domain Age, Domain End, iFrame,
    #  Mouse Over, Right Click, Web Forwards]
    
    return safe_features_zero

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

# Enhanced URL validation
def validate_url(url):
    # Basic checks
    if not url or len(url) < 5:
        return False
        
    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    # Use standard validator
    return validators.url(url)

# Load the model with error handling and version validation
try:
    # Ensure models directory exists
    if not os.path.exists('models'):
        logger.warning("Models directory does not exist. Creating it.")
        os.makedirs('models')
        
    model_file = 'models/XGBoostClassifier.pickle.dat'
    
    if not os.path.exists(model_file):
        logger.error(f"Model file {model_file} not found")
        model = None
    else:
        with open(model_file, 'rb') as file:
            model = pickle.load(file)
            
            # Validate model type
            if not hasattr(model, 'predict') or not hasattr(model, 'predict_proba'):
                logger.error("Loaded model doesn't have required methods")
                model = None
            else:
                logger.info(f"Model loaded successfully from {model_file}")
                
except Exception as e:
    logger.error(f"Model loading failed: {str(e)}")
    model = None

# Safe model prediction with error handling
def predict_safely(model, features):
    """Make a prediction with error handling"""
    if model is None:
        logger.error("Model not available for prediction")
        return None, None
        
    if features is None or len(features) != 16:
        logger.error(f"Invalid features for prediction: {features}")
        return None, None
        
    try:
        # Reshape and convert features
        features_array = np.array(features).reshape(1, -1)
        
        # Make prediction
        prediction = model.predict(features_array)[0]
        prediction = convert_to_json_serializable(prediction)
        
        # Get probabilities
        probabilities = model.predict_proba(features_array)[0]
        probabilities = [convert_to_json_serializable(p) for p in probabilities]
        
        # In most phishing datasets, 1=phishing, 0=legitimate
        is_phishing = bool(prediction == 1)
        
        # Calculate confidence
        raw_confidence = probabilities[1] if is_phishing else probabilities[0]
        
        return is_phishing, raw_confidence
        
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        logger.error(traceback.format_exc())
        return None, None

@app.route('/')
def home():
    # Check if model is loaded
    if model is None:
        return render_template('error.html', 
                              error="Model is not loaded. Please check server logs.")
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    # Generate a request ID for tracking
    request_id = f"req_{int(time.time())}_{random.randint(1000, 9999)}"
    logger.info(f"[{request_id}] New prediction request")
    
    if model is None:
        logger.error(f"[{request_id}] Model not loaded")
        return jsonify({
            'success': False,
            'error': 'Model is not loaded. Please check server configuration.',
            'request_id': request_id
        })
    
    start_time = time.time()
    
    try:
        # Get URL from form
        url = request.form.get('url')
        
        # Basic validation
        if not url:
            logger.warning(f"[{request_id}] No URL provided")
            return jsonify({
                'success': False,
                'error': 'No URL provided',
                'request_id': request_id
            })
        
        # Enhanced URL validation
        original_url = url
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            logger.info(f"[{request_id}] Added http:// prefix to URL: {url}")
        
        # Full URL validation
        if not validators.url(url):
            logger.warning(f"[{request_id}] Invalid URL format: {url}")
            return jsonify({
                'success': False,
                'error': 'Invalid URL format. Please enter a valid URL including http:// or https://',
                'request_id': request_id
            })
        
        logger.info(f"[{request_id}] Processing URL: {url}")
        
        # Extract domain for logging
        domain = extract_domain(url)
        
        # STEP 1: Check if domain is trusted (fastest check)
        trusted_start = time.time()
        is_trusted = is_trusted_domain(url)
        trusted_time = time.time() - trusted_start
        
        if is_trusted:
            logger.info(f"[{request_id}] URL {url} is in trusted domains list (check took {trusted_time:.3f}s)")
            
            # For trusted domains, skip feature extraction and return safe features
            safe_features = get_safe_features()
            feature_info = format_features_for_display(safe_features)
                
            response_time = time.time() - start_time
            logger.info(f"[{request_id}] Trusted domain response in {response_time:.3f}s")
            
            return jsonify({
                'success': True,
                'url': url,
                'is_phishing': False,
                'confidence': 99.5,
                'features': feature_info,
                'source': 'Trusted Domain',
                'trusted': True,
                'processing_time': response_time,
                'request_id': request_id
            })
        
        # STEP 2: Check against Google Safe Browsing API
        sb_start = time.time()
        safe_browsing_result = get_safe_browsing_result(url)
        sb_time = time.time() - sb_start
        
        if safe_browsing_result and not safe_browsing_result['safe']:
            logger.warning(f"[{request_id}] URL {url} is flagged as unsafe by Google Safe Browsing (check took {sb_time:.3f}s)")
            
            # Get threat types for display
            threat_types = safe_browsing_result.get('threat_types', ['Unknown threat'])
            threat_description = ', '.join(threat_types)
            
            # Extract features in the background for display purposes
            # but don't wait for the results
            threading.Thread(
                target=lambda: extract_features_safely(url),
                daemon=True
            ).start()
            
            response_time = time.time() - start_time
            logger.info(f"[{request_id}] Safe Browsing detection response in {response_time:.3f}s")
            
            # For unsafe URLs, return immediate response
            return jsonify({
                'success': True,
                'url': url,
                'is_phishing': True,
                'confidence': 98.5,  # High confidence for Safe Browsing matches
                'features': [],  # No need for detailed features
                'source': 'Google Safe Browsing',
                'threat_description': threat_description,
                'processing_time': response_time,
                'request_id': request_id
            })
        
        # STEP 3: Extract features and use ML model
        features_start = time.time()
        features = extract_features_safely(url)
        features_time = time.time() - features_start
        
        if features is None:
            logger.error(f"[{request_id}] Feature extraction failed for {url}")
            return jsonify({
                'success': False,
                'error': 'Could not extract features from the provided URL',
                'url': url,
                'request_id': request_id
            })
            
        logger.info(f"[{request_id}] Features extracted in {features_time:.3f}s: {features}")
        
        # STEP 4: Make prediction with the model
        pred_start = time.time()
        is_phishing, raw_confidence = predict_safely(model, features)
        pred_time = time.time() - pred_start
        
        if is_phishing is None:
            logger.error(f"[{request_id}] Prediction failed for {url}")
            return jsonify({
                'success': False,
                'error': 'Error making prediction with the model',
                'url': url,
                'request_id': request_id
            })
            
        logger.info(f"[{request_id}] Prediction made in {pred_time:.3f}s: {'Phishing' if is_phishing else 'Legitimate'} (confidence: {raw_confidence:.4f})")
        
        # STEP 5: Calculate confidence score
        try:
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
            logger.error(f"[{request_id}] Error calculating probability: {str(prob_err)}")
            confidence_percentage = 89.5  # Default confidence
        
        # Format features for display
        feature_info = format_features_for_display(features)
        
        # STEP 6: Prepare and send response
        result = {
            'success': True,
            'url': url,
            'is_phishing': is_phishing,
            'confidence': confidence_percentage,
            'features': feature_info,
            'source': 'Safe Browsing + ML Model' if safe_browsing_result else 'ML Model',
            'trusted': False,
            'processing_time': time.time() - start_time,
            'request_id': request_id
        }
        
        logger.info(f"[{request_id}] Total processing time: {result['processing_time']:.3f}s")
        return jsonify(result)
    
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"[{request_id}] Unexpected error after {processing_time:.3f}s: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': f'Error analyzing URL: {str(e)}',
            'processing_time': processing_time,
            'request_id': request_id
        })

@app.route('/api/check', methods=['POST'])
def api_check():
    # Generate request ID
    request_id = f"api_{int(time.time())}_{random.randint(1000, 9999)}"
    
    if model is None:
        return jsonify({
            'success': False,
            'error': 'Model is not loaded. Please check server configuration.',
            'request_id': request_id
        })
        
    start_time = time.time()
        
    try:
        # Get data from JSON request
        data = request.get_json()
        
        # Handle case when request is not JSON
        if data is None:
            return jsonify({
                'success': False,
                'error': 'Invalid request format. Expected JSON.',
                'request_id': request_id
            })
            
        url = data.get('url')
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL not provided',
                'request_id': request_id
            })
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        if not validators.url(url):
            return jsonify({
                'success': False,
                'error': 'Invalid URL format',
                'request_id': request_id
            })
            
        # Check if in trusted domains
        if is_trusted_domain(url):
            logger.info(f"[{request_id}] API request: URL {url} is in trusted domains list")
            return jsonify({
                'success': True,
                'url': url,
                'is_phishing': False,
                'confidence': 99.5,
                'source': 'Trusted Domain',
                'trusted': True,
                'processing_time': time.time() - start_time,
                'request_id': request_id
            })
        
        # Check against Google Safe Browsing API
        safe_browsing_result = get_safe_browsing_result(url)
        if safe_browsing_result and not safe_browsing_result['safe']:
            logger.warning(f"[{request_id}] API request: URL {url} is flagged as unsafe by Google Safe Browsing")
            
            # For unsafe URLs, return immediate response
            return jsonify({
                'success': True,
                'url': url,
                'is_phishing': True,
                'confidence': 98.5,
                'source': 'Google Safe Browsing',
                'threat_types': safe_browsing_result.get('threat_types', ['Unknown threat']),
                'processing_time': time.time() - start_time,
                'request_id': request_id
            })
            
        # Extract features safely
        features = extract_features_safely(url)
        
        if features is None:
            return jsonify({
                'success': False,
                'error': 'Feature extraction failed',
                'url': url,
                'request_id': request_id
            })
        
        # Make prediction safely
        is_phishing, raw_confidence = predict_safely(model, features)
        
        if is_phishing is None:
            return jsonify({
                'success': False,
                'error': 'Prediction failed',
                'url': url,
                'request_id': request_id
            })
        
        # Calculate confidence
        confidence_percentage = 85 + ((raw_confidence - 0.5) * 30)
        confidence_percentage = min(max(confidence_percentage, 85), 95)
        confidence_percentage = round(confidence_percentage, 1)
        
        return jsonify({
            'success': True,
            'url': url,
            'is_phishing': is_phishing,
            'confidence': confidence_percentage,
            'source': 'Safe Browsing + ML Model' if safe_browsing_result else 'ML Model',
            'trusted': False,
            'processing_time': time.time() - start_time,
            'request_id': request_id
        })
        
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"[{request_id}] API error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': f'Error analyzing URL: {str(e)}',
            'processing_time': processing_time,
            'request_id': request_id
        })

@app.route('/api/trust', methods=['POST'])
def trust_url():
    request_id = f"trust_{int(time.time())}_{random.randint(1000, 9999)}"
    start_time = time.time()
    
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'success': False,
                'error': 'URL not provided',
                'request_id': request_id
            })
            
        url = data.get('url')
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        if not validators.url(url):
            return jsonify({
                'success': False,
                'error': 'Invalid URL format',
                'request_id': request_id
            })
            
        # Try to add to trusted domains
        result = add_trusted_domain(url)
        
        if result:
            logger.info(f"[{request_id}] Added {url} to trusted domains")
            # Clear any cached feature extraction results for this domain
            domain = extract_domain(url)
            for key in list(feature_extraction_cache.keys()):
                if domain in key:
                    del feature_extraction_cache[key]
                    
            return jsonify({
                'success': True,
                'message': f'Added domain to trusted list',
                'processing_time': time.time() - start_time,
                'request_id': request_id
            })
        else:
            logger.info(f"[{request_id}] Domain {url} is already trusted or couldn't be added")
            return jsonify({
                'success': False,
                'error': 'Domain is already trusted or could not be added',
                'processing_time': time.time() - start_time,
                'request_id': request_id
            })
            
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f"[{request_id}] Trust URL error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Error processing request: {str(e)}',
            'processing_time': processing_time,
            'request_id': request_id
        })

@app.route('/health', methods=['GET'])
def health_check():
    # Check model status
    model_status = "loaded" if model is not None else "not_loaded"
    
    # Check Safe Browsing API
    safe_browsing_status = "enabled" if SAFE_BROWSING_API_KEY else "disabled"
    
    # Check feature extraction
    try:
        test_features = extract_features_safely("https://www.google.com", use_cache=True)
        feature_extraction_status = "working" if test_features is not None else "failing"
    except:
        feature_extraction_status = "failing"
    
    # Get stats on caches
    sb_cache_count = len(safe_browsing_cache)
    feature_cache_count = len(feature_extraction_cache)
    
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'uptime': 'N/A',  # Could track app start time to calculate this
        'model_status': model_status,
        'safe_browsing': safe_browsing_status,
        'feature_extraction': feature_extraction_status,
        'caches': {
            'safe_browsing_entries': sb_cache_count,
            'feature_extraction_entries': feature_cache_count
        }
    })

@app.route('/clear_cache', methods=['POST'])
def clear_cache():
    """Admin endpoint to clear the caches"""
    # Simple "authentication" - just a secret in the request
    secret = request.form.get('secret')
    if not secret or secret != os.environ.get('ADMIN_SECRET', 'phishing_admin'):
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    try:
        # Clear the caches
        safe_browsing_cache.clear()
        feature_extraction_cache.clear()
        
        return jsonify({
            'success': True,
            'message': 'Caches cleared successfully',
            'sb_cache_size': len(safe_browsing_cache),
            'feature_cache_size': len(feature_extraction_cache)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error clearing cache: {str(e)}'
        })

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'success': False, 'error': 'Internal server error', 'details': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting Phishing Detection Server")
    
    # Check if the model file exists
    model_file = 'models/XGBoostClassifier.pickle.dat'
    if not os.path.exists(model_file):
        logger.error(f"Model file not found: {model_file}")
        logger.info("Server will start but predictions will fail until model is available")
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)