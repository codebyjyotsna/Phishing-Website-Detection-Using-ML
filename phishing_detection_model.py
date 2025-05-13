import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import re
from urllib.parse import urlparse

# Feature Extraction Function
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['num_subdomains'] = len(urlparse(url).netloc.split('.')) - 2
    features['has_https'] = 1 if 'https' in url else 0
    return features

# Load dataset (replace 'phishing_urls.csv' with your dataset path)
data = pd.read_csv('phishing_urls.csv')  # Dataset should have 'url' and 'label' columns
data['features'] = data['url'].apply(lambda x: extract_features(x))
features_df = pd.DataFrame(data['features'].tolist())
X = features_df
y = data['label']

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train a Random Forest Classifier
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Evaluate Model
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")

# Save Model
joblib.dump(model, 'phishing_model.pkl')
