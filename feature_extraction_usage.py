from advanced_feature_extraction import URLFeatureExtractor

# Initialize the extractor
extractor = URLFeatureExtractor()

# Example URLs
urls = [
    "https://www.example.com",
    "http://123.45.67.89",
    "https://secure-login.tk",
    "http://phishing-site.gq"
]

# Extract features for each URL
for url in urls:
    features = extractor.extract_features(url)
    print(f"Features for {url}:")
    print(features)
    print()
