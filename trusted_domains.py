import os
import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Constants
TRUSTED_DOMAINS_FILE = 'trusted_domains.json'

# Initial set of trusted domains
DEFAULT_TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "stackoverflow.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "facebook.com", 
    "youtube.com",
    "linkedin.com",
    "twitter.com",
    "instagram.com",
    "netflix.com",
    "wikipedia.org",
    "yahoo.com",
    "python.org",
    "codechef.com",
    "hackerrank.com",
    "leetcode.com",
    "medium.com",
    "udemy.com",
    "coursera.org",
    "hotstar.com",
    "spotify.com",
    "whatsapp.com",
    "telegram.org",
    "reddit.com",
    "quora.com",
    "pinterest.com",
    "rbunagpur.in",
}

# Global variable to hold the trusted domains set
trusted_domains = set()

def load_trusted_domains():
    """Load trusted domains from file or create with defaults if not exists"""
    global trusted_domains
    
    try:
        if os.path.exists(TRUSTED_DOMAINS_FILE):
            with open(TRUSTED_DOMAINS_FILE, 'r') as f:
                domains = json.load(f)
                trusted_domains = set(domains)
                logger.info(f"Loaded {len(trusted_domains)} trusted domains from file")
        else:
            # Create file with default domains
            trusted_domains = DEFAULT_TRUSTED_DOMAINS
            save_trusted_domains()
            logger.info(f"Created trusted domains file with {len(trusted_domains)} default domains")
    except Exception as e:
        logger.error(f"Error loading trusted domains: {str(e)}")
        trusted_domains = DEFAULT_TRUSTED_DOMAINS
        logger.info(f"Using {len(trusted_domains)} default trusted domains")

def save_trusted_domains():
    """Save trusted domains to file"""
    try:
        with open(TRUSTED_DOMAINS_FILE, 'w') as f:
            json.dump(list(trusted_domains), f, indent=2)
        logger.info(f"Saved {len(trusted_domains)} trusted domains to file")
        return True
    except Exception as e:
        logger.error(f"Error saving trusted domains: {str(e)}")
        return False

def extract_domain(url):
    """Extract domain from URL"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove 'www.' if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain
    except:
        return url

def is_trusted_domain(url):
    """Check if a URL's domain is in the trusted list"""
    try:
        domain = extract_domain(url)
        
        # Check if this exact domain is trusted
        if domain in trusted_domains:
            return True
            
        # Check parent domains
        parts = domain.split('.')
        if len(parts) > 2:
            parent_domain = '.'.join(parts[-2:])  # e.g., example.com from sub.example.com
            if parent_domain in trusted_domains:
                return True
                
        return False
    except Exception as e:
        logger.error(f"Error checking trusted domain: {str(e)}")
        return False

def add_trusted_domain(url):
    """Add a URL's domain to trusted domains list"""
    try:
        domain = extract_domain(url)
        
        # Don't add if already trusted
        if is_trusted_domain(url):
            return False
        
        # Strip to parent domain (e.g. example.com from sub.example.com)
        parts = domain.split('.')
        if len(parts) > 2:
            domain = '.'.join(parts[-2:])
            
        trusted_domains.add(domain)
        save_trusted_domains()
        return True
    except Exception as e:
        logger.error(f"Error adding trusted domain: {str(e)}")
        return False

# Load domains when module is imported
load_trusted_domains()