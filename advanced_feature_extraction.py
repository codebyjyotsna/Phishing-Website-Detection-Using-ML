import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import ssl
import socket

# Feature Extraction Class
class URLFeatureExtractor:
    def __init__(self):
        pass

    def extract_features(self, url):
        """Extract all features from a URL."""
        features = {}
        features.update(self.url_based_features(url))
        features.update(self.html_based_features(url))
        features.update(self.ssl_based_features(url))
        return features

    def url_based_features(self, url):
        """Extract URL-based features."""
        features = {}
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # URL length
        features['url_length'] = len(url)
        # Presence of IP address
        features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        # Number of subdomains
        features['num_subdomains'] = len(domain.split('.')) - 2
        # Presence of "@" symbol
        features['has_at_symbol'] = 1 if '@' in url else 0
        # Presence of "-" in the domain
        features['has_hyphen'] = 1 if '-' in domain else 0
        # Starts with HTTPS
        features['starts_with_https'] = 1 if url.startswith('https') else 0
        # Suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        features['suspicious_tld'] = 1 if any(url.endswith(tld) for tld in suspicious_tlds) else 0

        return features

    def html_based_features(self, url):
        """Extract HTML-based features using BeautifulSoup."""
        features = {}
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Count number of <script> tags
            features['num_script_tags'] = len(soup.find_all('script'))
            # Count number of <iframe> tags
            features['num_iframe_tags'] = len(soup.find_all('iframe'))
            # Check for phishing keywords in HTML
            phishing_keywords = ['login', 'verify', 'secure', 'bank']
            features['has_phishing_keywords'] = 1 if any(keyword in soup.text.lower() for keyword in phishing_keywords) else 0
            # Presence of forms
            features['has_forms'] = 1 if soup.find('form') else 0

        except Exception as e:
            # If the request fails, set default values
            features['num_script_tags'] = -1
            features['num_iframe_tags'] = -1
            features['has_phishing_keywords'] = -1
            features['has_forms'] = -1

        return features

    def ssl_based_features(self, url):
        """Extract SSL-based features using the `ssl` and `socket` libraries."""
        features = {}
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # SSL certificate validity period
                    features['ssl_valid_days'] = (cert['notAfter'] - cert['notBefore']).days
                    # Issuer organization
                    features['ssl_issuer'] = cert['issuer'][0][0][1]

        except Exception as e:
            # If SSL fails, set default values
            features['ssl_valid_days'] = -1
            features['ssl_issuer'] = 'unknown'

        return features
