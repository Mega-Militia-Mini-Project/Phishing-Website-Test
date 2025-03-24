import re
import urllib.parse
import socket
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import whois

# Shortening Services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# Feature extraction functions
def have_ip_address(url):
    # Check if URL contains IP
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    return 1 if match else 0

def have_at_symbol(url):
    # Check if URL contains @ symbol
    return 1 if re.search("@", url) else 0

def url_length(url):
    # Check URL length
    return 1 if len(url) < 54 else 0

def url_depth(url):
    # Count how many / in URL
    s = urllib.parse.urlparse(url).path.split('/')
    depth = 0
    for dir in s:
        if len(dir) > 0:
            depth += 1
    return depth

def redirection(url):
    # Check for redirections in URL
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

def https_domain(url):
    # Check if domain has HTTPS
    domain = urllib.parse.urlparse(url).netloc
    return 1 if 'https' in url and domain else 0

def tiny_url(url):
    # Check if URL uses shortening services
    match = re.search(shortening_services, url)
    return 1 if match else 0

def prefix_suffix(url):
    # Check for - in domain
    domain = urllib.parse.urlparse(url).netloc
    return 1 if '-' in domain else 0

def dns_record(domain):
    # Check if domain has DNS record
    try:
        socket.gethostbyname(domain)
        return 0  # Domain has DNS record (legitimate)
    except:
        return 1  # Domain doesn't have DNS record (phishing)

def web_traffic(url):
    try:
        # Use Alexa data to check website ranking
        rank = BeautifulSoup(requests.get("http://data.alexa.com/data?cli=10&dat=s&url=" + url).text, "xml").find("REACH")['RANK']
        return 1 if int(rank) < 100000 else 0
    except:
        return 0  # Low traffic

def domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        
        # Handling multiple creation dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        today = datetime.now()
        age = (today - creation_date).days
        return 1 if age > 180 else 0  # Domains older than 6 months are considered legitimate
    except:
        return 0

def domain_end(domain):
    # Check if domain expires in less than 1 year
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        
        # Handling multiple expiration dates
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        today = datetime.now()
        end = (expiration_date - today).days
        return 1 if end > 365 else 0  # Domains expiring in more than a year are legitimate
    except:
        return 0

def iframe(response):
    try:
        # Check if iframe is used
        if re.search('<iframe', response.text, re.IGNORECASE):
            return 1
        else:
            return 0
    except:
        return 0

def mouse_over(response):
    try:
        # Check for onMouseOver events
        if re.search("onmouseover", response.text, re.IGNORECASE):
            return 1
        else:
            return 0
    except:
        return 0

def right_click(response):
    try:
        # Check if right click is disabled
        if re.search("event.button ?== ?2", response.text, re.IGNORECASE):
            return 1
        else:
            return 0
    except:
        return 0

def web_forwards(response):
    try:
        # Check for meta/iframe redirections
        if len(response.history) > 1 or re.search("<meta http-equiv=\"refresh\"", response.text, re.IGNORECASE):
            return 1
        else:
            return 0
    except:
        return 0

def featureExtraction(url):
    try:
        domain = urllib.parse.urlparse(url).netloc
        
        # Safe request with timeout
        try:
            response = requests.get(url, timeout=5)
        except:
            response = None
        
        features = []
        
        # Add all features
        features.append(have_ip_address(url))
        features.append(have_at_symbol(url))
        features.append(url_length(url))
        features.append(url_depth(url))
        features.append(redirection(url))
        features.append(https_domain(url))
        features.append(tiny_url(url))
        features.append(prefix_suffix(url))
        
        # These features may fail for some URLs, so use try/except
        try:
            features.append(dns_record(domain))
        except:
            features.append(1)
            
        features.append(web_traffic(url))
        features.append(domain_age(domain))
        features.append(domain_end(domain))
        
        # These features need response content
        if response:
            features.append(iframe(response))
            features.append(mouse_over(response))
            features.append(right_click(response))
            features.append(web_forwards(response))
        else:
            # Default values if response fails
            features.append(0)
            features.append(0)
            features.append(0)
            features.append(0)
            
        return features
    except:
        # Return a list of zeros as fallback
        return [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]