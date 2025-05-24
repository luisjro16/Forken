import joblib

class Model:
    def __init__(self):
        self.model = joblib.load("rotor/rf_model.pkl")   

    def classify(self, df):
        
        return self.model.predict(df)