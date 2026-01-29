"""
Model training utilities for PrivGuard
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Tuple
from ai.classifier import EmailClassifier
import config
from utils.logger import logger

class ModelTrainer:
    """Train ML models for email classification"""
    
    def __init__(self):
        self.classifier = EmailClassifier()
    
    def train_from_csv(self, csv_path: str, text_column: str = 'text', 
                      label_column: str = 'label') -> float:
        """
        Train model from CSV file
        
        Args:
            csv_path: Path to CSV file
            text_column: Name of column with email text
            label_column: Name of column with labels
            
        Returns:
            Model accuracy
        """
        try:
            df = pd.read_csv(csv_path)
            
            if text_column not in df.columns or label_column not in df.columns:
                raise ValueError(f"CSV must contain '{text_column}' and '{label_column}' columns")
            
            emails = df[text_column].fillna('').tolist()
            labels = self._map_labels(df[label_column].tolist())
            
            logger.info(f"Training on {len(emails)} samples")
            accuracy = self.classifier.train(emails, labels)
            
            return accuracy
            
        except Exception as e:
            logger.error(f"Error training from CSV: {str(e)}")
            raise
    
    def train_from_data(self, emails: List[str], labels: List[str]) -> float:
        """
        Train model from lists
        
        Args:
            emails: List of email texts
            labels: List of label strings ('safe', 'suspicious', 'malicious')
            
        Returns:
            Model accuracy
        """
        try:
            mapped_labels = self._map_labels(labels)
            accuracy = self.classifier.train(emails, mapped_labels)
            return accuracy
        except Exception as e:
            logger.error(f"Error training from data: {str(e)}")
            raise
    
    def _map_labels(self, labels: List[str]) -> List[int]:
        """
        Map label strings to integers
        
        Args:
            labels: List of label strings
            
        Returns:
            List of integer labels (0=safe, 1=suspicious, 2=malicious)
        """
        label_map = {
            'safe': 0,
            'suspicious': 1,
            'malicious': 2,
            'phishing': 2,
            'spam': 1,
            'ham': 0
        }
        
        mapped = []
        for label in labels:
            label_lower = str(label).lower()
            mapped.append(label_map.get(label_lower, 0))
        
        return mapped
    
    def generate_sample_data(self, output_path: str, num_samples: int = 100):
        """
        Generate sample training data
        
        Args:
            output_path: Path to save CSV
            num_samples: Number of samples to generate
        """
        samples = []
        
        # Safe emails
        safe_samples = [
            "Meeting reminder for tomorrow at 2 PM",
            "Thank you for your purchase",
            "Your order has been shipped",
            "Newsletter: Weekly updates",
            "Password reset confirmation"
        ]
        
        # Suspicious emails
        suspicious_samples = [
            "Urgent: Verify your account immediately",
            "Click here to claim your prize",
            "Limited time offer - act now",
            "Your account will be suspended",
            "Verify your email address"
        ]
        
        # Malicious emails
        malicious_samples = [
            "Click here to verify your account or it will be deleted",
            "Urgent: Your account has been compromised. Login now",
            "You have won $1000000. Click to claim",
            "Verify your PayPal account or it will be suspended",
            "Security alert: Unusual activity detected. Click to verify"
        ]
        
        import random
        
        for _ in range(num_samples // 3):
            samples.append({
                'text': random.choice(safe_samples),
                'label': 'safe'
            })
        
        for _ in range(num_samples // 3):
            samples.append({
                'text': random.choice(suspicious_samples),
                'label': 'suspicious'
            })
        
        for _ in range(num_samples - len(samples)):
            samples.append({
                'text': random.choice(malicious_samples),
                'label': 'malicious'
            })
        
        df = pd.DataFrame(samples)
        df.to_csv(output_path, index=False)
        logger.info(f"Generated sample data: {output_path}")
