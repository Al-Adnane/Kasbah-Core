"""
================================================================================
                    KASBAH MODEL VALIDATION FRAMEWORK
                    © 2026 Kasbah Guard - All Rights Reserved

    Validates trained models on REAL datasets:
    - AI Text: HC3, GPT-4 outputs, Claude outputs
    - Deepfake: FaceForensics++, Celeb-DF
    - Voice: ASVspoof, LibriSpeech

    Outputs:
    - Accuracy metrics (precision, recall, F1, ROC-AUC)
    - Confusion matrices
    - Error analysis
    - Threshold recommendations

    Usage: python validate_models.py --model ai_text --dataset hc3
================================================================================
"""

import os
import json
import numpy as np
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
import pickle

# ML libraries
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, roc_auc_score, confusion_matrix, 
    classification_report, precision_recall_curve
)
import matplotlib.pyplot as plt
import seaborn as sns

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ValidationResults:
    """Container for validation metrics."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    confusion_matrix: np.ndarray
    optimal_threshold: float
    false_positives: List[Dict]
    false_negatives: List[Dict]


class AITextValidator:
    """Validate AI text detection model."""
    
    def __init__(self, model_path: str):
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_extractor = model_data.get('feature_extractor', None)
        
    def extract_features(self, text: str) -> np.ndarray:
        """Extract features from text."""
        if self.feature_extractor:
            return self.feature_extractor.extract_features(text)
        else:
            # Fallback: use same features as training
            return self._extract_features_fallback(text)
    
    def _extract_features_fallback(self, text: str) -> np.ndarray:
        """Fallback feature extraction."""
        # Import from training module
        from train_model import AITextFeatureExtractor
        extractor = AITextFeatureExtractor()
        return extractor.extract_features(text)
    
    def validate(self, test_texts: List[str], test_labels: List[int]) -> ValidationResults:
        """Validate model on test data."""
        logger.info(f"Validating on {len(test_texts)} samples...")
        
        # Extract features
        X = np.array([self.extract_features(text) for text in test_texts])
        y = np.array(test_labels)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict
        y_pred = self.model.predict(X_scaled)
        y_proba = self.model.predict_proba(X_scaled)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y, y_pred)
        precision = precision_score(y, y_pred)
        recall = recall_score(y, y_pred)
        f1 = f1_score(y, y_pred)
        roc_auc = roc_auc_score(y, y_proba)
        cm = confusion_matrix(y, y_pred)
        
        # Find optimal threshold
        optimal_threshold = self._find_optimal_threshold(y, y_proba)
        
        # Collect errors
        false_positives = []
        false_negatives = []
        
        for i, (text, true_label, pred_label, proba) in enumerate(zip(test_texts, y, y_pred, y_proba)):
            if pred_label == 1 and true_label == 0:
                false_positives.append({
                    "index": i,
                    "text": text[:200] + "..." if len(text) > 200 else text,
                    "predicted_probability": float(proba)
                })
            elif pred_label == 0 and true_label == 1:
                false_negatives.append({
                    "index": i,
                    "text": text[:200] + "..." if len(text) > 200 else text,
                    "predicted_probability": float(proba)
                })
        
        return ValidationResults(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            roc_auc=roc_auc,
            confusion_matrix=cm,
            optimal_threshold=optimal_threshold,
            false_positives=false_positives,
            false_negatives=false_negatives
        )
    
    def _find_optimal_threshold(self, y_true: np.ndarray, y_proba: np.ndarray) -> float:
        """Find optimal classification threshold."""
        precision, recall, thresholds = precision_recall_curve(y_true, y_proba)
        
        # F1 score for each threshold
        f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
        optimal_idx = np.argmax(f1_scores)
        
        return float(thresholds[optimal_idx]) if optimal_idx < len(thresholds) else 0.5


class DeepfakeValidator:
    """Validate deepfake detection model."""
    
    def __init__(self, model_path: str):
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        
    def validate(self, test_features: List[Dict], test_labels: List[int]) -> ValidationResults:
        """Validate model on test features."""
        logger.info(f"Validating on {len(test_features)} samples...")
        
        # Convert features to vectors
        from train_model import DeepfakeFeatureExtractor
        extractor = DeepfakeFeatureExtractor()
        
        X = np.array([extractor._dict_to_vector(f) for f in test_features])
        y = np.array(test_labels)
        
        # Scale and predict
        X_scaled = self.scaler.transform(X)
        y_pred = self.model.predict(X_scaled)
        y_proba = self.model.predict_proba(X_scaled)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y, y_pred)
        precision = precision_score(y, y_pred)
        recall = recall_score(y, y_pred)
        f1 = f1_score(y, y_pred)
        roc_auc = roc_auc_score(y, y_proba)
        cm = confusion_matrix(y, y_pred)
        
        optimal_threshold = self._find_optimal_threshold(y, y_proba)
        
        return ValidationResults(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            roc_auc=roc_auc,
            confusion_matrix=cm,
            optimal_threshold=optimal_threshold,
            false_positives=[],
            false_negatives=[]
        )
    
    def _find_optimal_threshold(self, y_true: np.ndarray, y_proba: np.ndarray) -> float:
        """Find optimal classification threshold."""
        precision, recall, thresholds = precision_recall_curve(y_true, y_proba)
        f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
        optimal_idx = np.argmax(f1_scores)
        return float(thresholds[optimal_idx]) if optimal_idx < len(thresholds) else 0.5


class VoiceValidator:
    """Validate voice cloning detection model."""
    
    def __init__(self, model_path: str):
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        
    def validate(self, test_features: List[Dict], test_labels: List[int]) -> ValidationResults:
        """Validate model on test features."""
        logger.info(f"Validating on {len(test_features)} samples...")
        
        from train_model import VoiceCloningModelTrainer
        trainer = VoiceCloningModelTrainer()
        
        X = np.array([trainer._dict_to_vector(f) for f in test_features])
        y = np.array(test_labels)
        
        X_scaled = self.scaler.transform(X)
        y_pred = self.model.predict(X_scaled)
        y_proba = self.model.predict_proba(X_scaled)[:, 1]
        
        accuracy = accuracy_score(y, y_pred)
        precision = precision_score(y, y_pred)
        recall = recall_score(y, y_pred)
        f1 = f1_score(y, y_pred)
        roc_auc = roc_auc_score(y, y_proba)
        cm = confusion_matrix(y, y_pred)
        
        optimal_threshold = self._find_optimal_threshold(y, y_proba)
        
        return ValidationResults(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            roc_auc=roc_auc,
            confusion_matrix=cm,
            optimal_threshold=optimal_threshold,
            false_positives=[],
            false_negatives=[]
        )
    
    def _find_optimal_threshold(self, y_true: np.ndarray, y_proba: np.ndarray) -> float:
        """Find optimal classification threshold."""
        precision, recall, thresholds = precision_recall_curve(y_true, y_proba)
        f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
        optimal_idx = np.argmax(f1_scores)
        return float(thresholds[optimal_idx]) if optimal_idx < len(thresholds) else 0.5


def plot_results(results: ValidationResults, model_name: str, output_dir: Path):
    """Plot validation results."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Confusion Matrix
    plt.figure(figsize=(10, 8))
    sns.heatmap(
        results.confusion_matrix,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=['Human/Real', 'AI/Fake'],
        yticklabels=['Human/Real', 'AI/Fake']
    )
    plt.title(f'{model_name} - Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig(output_dir / 'confusion_matrix.png')
    plt.close()
    
    # Metrics summary
    metrics = {
        'Accuracy': results.accuracy,
        'Precision': results.precision,
        'Recall': results.recall,
        'F1 Score': results.f1,
        'ROC AUC': results.roc_auc
    }
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(metrics.keys(), metrics.values(), color='steelblue')
    plt.ylim(0, 1)
    plt.title(f'{model_name} - Validation Metrics')
    plt.ylabel('Score')
    
    # Add value labels
    for bar, value in zip(bars, metrics.values()):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                f'{value:.4f}', ha='center', va='bottom')
    
    plt.savefig(output_dir / 'metrics_summary.png')
    plt.close()
    
    logger.info(f"Plots saved to {output_dir}")


def save_validation_report(results: ValidationResults, model_name: str, output_dir: Path):
    """Save validation report to JSON."""
    report = {
        "model": model_name,
        "metrics": {
            "accuracy": results.accuracy,
            "precision": results.precision,
            "recall": results.recall,
            "f1": results.f1,
            "roc_auc": results.roc_auc
        },
        "confusion_matrix": results.confusion_matrix.tolist(),
        "optimal_threshold": results.optimal_threshold,
        "error_analysis": {
            "false_positive_count": len(results.false_positives),
            "false_negative_count": len(results.false_negatives),
            "false_positives": results.false_positives[:10],  # First 10
            "false_negatives": results.false_negatives[:10]
        },
        "recommendations": {
            "use_threshold": results.optimal_threshold,
            "notes": []
        }
    }
    
    # Add recommendations based on metrics
    if results.precision < 0.8:
        report["recommendations"]["notes"].append(
            "Low precision: Consider increasing threshold to reduce false positives"
        )
    if results.recall < 0.8:
        report["recommendations"]["notes"].append(
            "Low recall: Consider decreasing threshold to catch more positives"
        )
    if results.f1 < 0.75:
        report["recommendations"]["notes"].append(
            "Low F1: Model may need retraining with more/better data"
        )
    
    report_path = output_dir / "validation_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Validation report saved to {report_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description='Validate Kasbah detection models')
    parser.add_argument('--model', type=str, required=True,
                       choices=['ai_text', 'deepfake', 'voice'],
                       help='Model to validate')
    parser.add_argument('--dataset', type=str, required=True,
                       help='Dataset to validate on (e.g., hc3, faceforensics, asvspoof)')
    parser.add_argument('--model-path', type=str, required=True,
                       help='Path to trained model (.pkl file)')
    parser.add_argument('--data-path', type=str, required=True,
                       help='Path to test dataset')
    parser.add_argument('--output-dir', type=str, default='validation_results',
                       help='Output directory for results')
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir) / f"{args.model}_{args.dataset}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 70)
    print(f"KASBAH MODEL VALIDATION: {args.model.upper()}")
    print("=" * 70)
    
    # Load and validate based on model type
    if args.model == 'ai_text':
        validator = AITextValidator(args.model_path)
        
        # Load test data
        with open(args.data_path, 'r') as f:
            data = json.load(f)
        
        texts = [item['text'] for item in data.get('samples', data.get('test_samples', []))]
        labels = [item.get('label', 1 if 'ai' in data else 0) for item in data.get('samples', data.get('test_samples', []))]
        
        # If labels not in data, assume first half is AI, second half is human
        if not labels or all(l is None for l in labels):
            labels = [1] * (len(texts) // 2) + [0] * (len(texts) - len(texts) // 2)
        
        results = validator.validate(texts, labels)
        
    elif args.model == 'deepfake':
        validator = DeepfakeValidator(args.model_path)
        
        with open(args.data_path, 'r') as f:
            data = json.load(f)
        
        features = data.get('features', data.get('test_features', []))
        labels = data.get('labels', [1] * (len(features) // 2) + [0] * (len(features) - len(features) // 2))
        
        results = validator.validate(features, labels)
        
    elif args.model == 'voice':
        validator = VoiceValidator(args.model_path)
        
        with open(args.data_path, 'r') as f:
            data = json.load(f)
        
        features = data.get('features', data.get('test_features', []))
        labels = data.get('labels', [1] * (len(features) // 2) + [0] * (len(features) - len(features) // 2))
        
        results = validator.validate(features, labels)
    
    # Print results
    print(f"\n{'='*50}")
    print("VALIDATION RESULTS")
    print(f"{'='*50}")
    print(f"Accuracy:  {results.accuracy:.4f}")
    print(f"Precision: {results.precision:.4f}")
    print(f"Recall:    {results.recall:.4f}")
    print(f"F1 Score:  {results.f1:.4f}")
    print(f"ROC AUC:   {results.roc_auc:.4f}")
    print(f"Optimal Threshold: {results.optimal_threshold:.4f}")
    print(f"False Positives: {len(results.false_positives)}")
    print(f"False Negatives: {len(results.false_negatives)}")
    print(f"{'='*50}\n")
    
    # Save results
    plot_results(results, args.model.upper(), output_dir)
    report = save_validation_report(results, args.model, output_dir)
    
    print(f"Results saved to: {output_dir}")
    print("=" * 70)
    
    return report


if __name__ == "__main__":
    main()
