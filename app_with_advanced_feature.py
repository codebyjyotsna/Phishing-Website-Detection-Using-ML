from flask import Flask, request, jsonify
import joblib
from advanced_feature_extraction import URLFeatureExtractor

app = Flask(__name__)
model = joblib.load('phishing_model.pkl')
extractor = URLFeatureExtractor()

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url', '')
    features = extractor.extract_features(url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    result = 'phishing' if prediction == 1 else 'legitimate'
    return jsonify({'url': url, 'prediction': result})

if __name__ == '__main__':
    app.run(debug=True)
