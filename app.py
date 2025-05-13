from flask import Flask, request, jsonify
import joblib
import pandas as pd

app = Flask(__name__)
model = joblib.load('phishing_model.pkl')

# Feature Extraction Function
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['num_subdomains'] = len(urlparse(url).netloc.split('.')) - 2
    features['has_https'] = 1 if 'https' in url else 0
    return features

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url', '')
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    result = 'phishing' if prediction == 1 else 'legitimate'
    return jsonify({'url': url, 'prediction': result})

if __name__ == '__main__':
    app.run(debug=True)
