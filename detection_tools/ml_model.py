import joblib

def load_model():
    try:
        model = joblib.load("traffic_classifier.pkl")
        print("[ML] Model loaded successfully.")
        return model
    except Exception as e:
        print(f"[ML] Model loading error: {e}")
        return None

def predict(model, features):
    if not model:
        return "Unknown"
    try:
        return model.predict([features])[0]
    except Exception as e:
        print(f"[ML] Prediction error: {e}")
        return "Unknown"
