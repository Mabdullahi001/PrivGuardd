"""
Machine Learning classifier for email threat detection
"""

import os
import joblib
import numpy as np
from typing import Dict, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import config
from utils.logger import logger

class EmailClassifier:
    """ML-based email threat classifier"""
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.model_path = config.MODELS_DIR / "email_classifier.pkl"
        self.vectorizer_path = config.MODELS_DIR / "vectorizer.pkl"
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained model if available"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                logger.info("Loaded pre-trained classifier model")
            else:
                logger.info("No pre-trained model found. Train a model first.")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
    
    def train(self, emails: list, labels: list, test_size: float = 0.2):
        """
        Train the classifier
        
        Args:
            emails: List of email texts
            labels: List of labels (0=safe, 1=suspicious, 2=malicious)
            test_size: Proportion of data for testing
        """
        try:
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                emails, labels, test_size=test_size, random_state=42
            )
            
            # Vectorize text
            self.vectorizer = TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                stop_words='english'
            )
            X_train_vec = self.vectorizer.fit_transform(X_train)
            X_test_vec = self.vectorizer.transform(X_test)
            
            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train_vec, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test_vec)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"Model trained. Accuracy: {accuracy:.2%}")
            logger.info(f"\nClassification Report:\n{classification_report(y_test, y_pred)}")
            
            # Save model
            self.save_model()
            
            return accuracy
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            raise
    
    def predict(self, email_text: str) -> Dict:
        """
        Predict threat level for email
        
        Args:
            email_text: Email text to classify
            
        Returns:
            Dictionary with prediction results
        """
        if self.model is None or self.vectorizer is None:
            logger.warning("Model not trained. Using default prediction.")
            return {
                'threat_level': config.THREAT_SAFE,
                'confidence': 0.5,
                'probabilities': {
                    'safe': 0.5,
                    'suspicious': 0.3,
                    'malicious': 0.2
                }
            }
        
        try:
            # Vectorize
            email_vec = self.vectorizer.transform([email_text])
            
            # Predict
            prediction = self.model.predict(email_vec)[0]
            probabilities = self.model.predict_proba(email_vec)[0]
            
            # Map to threat levels
            threat_map = {
                0: config.THREAT_SAFE,
                1: config.THREAT_SUSPICIOUS,
                2: config.THREAT_MALICIOUS
            }
            
            threat_level = threat_map.get(prediction, config.THREAT_SAFE)
            confidence = max(probabilities)
            
            result = {
                'threat_level': threat_level,
                'confidence': float(confidence),
                'probabilities': {
                    'safe': float(probabilities[0]) if len(probabilities) > 0 else 0.0,
                    'suspicious': float(probabilities[1]) if len(probabilities) > 1 else 0.0,
                    'malicious': float(probabilities[2]) if len(probabilities) > 2 else 0.0
                }
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error predicting: {str(e)}")
            return {
                'threat_level': config.THREAT_SAFE,
                'confidence': 0.0,
                'probabilities': {
                    'safe': 1.0,
                    'suspicious': 0.0,
                    'malicious': 0.0
                }
            }
    
    def save_model(self):
        """Save trained model and vectorizer"""
        try:
            if self.model is not None and self.vectorizer is not None:
                joblib.dump(self.model, self.model_path)
                joblib.dump(self.vectorizer, self.vectorizer_path)
                logger.info("Model saved successfully")
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
