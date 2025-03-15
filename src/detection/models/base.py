"""
Base classes for anomaly detection models

Defines common interfaces and functionality for all models

Version: 1.0.0
Last updated: 2025-03-15 18:21:40
Last updated by: Rahul
"""

import abc
import time
import json
import os
import pickle
from typing import Dict, Any, List, Tuple, Optional, Union, Callable
import numpy as np
import pandas as pd
from pathlib import Path
import uuid
from datetime import datetime

# Import ASIRA modules
from src.common.logging_config import get_logger

# Initialize logger
logger = get_logger("asira.detection.models")

class ModelConfig:
    """Configuration for anomaly detection models"""
    
    def __init__(self, config_dict: Dict[str, Any]):
        """
        Initialize model configuration
        
        Args:
            config_dict: Configuration dictionary
        """
        self.config = config_dict
        self.model_type = config_dict.get("model_type", "unknown")
        self.model_id = config_dict.get("model_id", f"{self.model_type}_{int(time.time())}")
        self.threshold = config_dict.get("threshold", 0.7)
        self.feature_names = config_dict.get("feature_names", [])
        self.version = config_dict.get("version", "1.0.0")
        self.created_at = config_dict.get("created_at", time.time())
        self.description = config_dict.get("description", "")
        self.tags = config_dict.get("tags", [])
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            "model_type": self.model_type,
            "model_id": self.model_id,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
            "version": self.version,
            "created_at": self.created_at,
            "description": self.description,
            "tags": self.tags,
            **self.config
        }
        
    def to_json(self, indent: int = 2) -> str:
        """Convert configuration to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)
        
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'ModelConfig':
        """Create configuration from dictionary"""
        return cls(config_dict)
        
    @classmethod
    def from_json(cls, json_str: str) -> 'ModelConfig':
        """Create configuration from JSON string"""
        config_dict = json.loads(json_str)
        return cls(config_dict)
        
    def validate(self) -> Tuple[bool, str]:
        """
        Validate configuration settings
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check required fields
        if not self.model_type:
            return False, "model_type is required"
        
        # Validate threshold
        if not 0 <= self.threshold <= 1:
            return False, f"threshold must be between 0 and 1, got {self.threshold}"
            
        return True, ""


class BaseModel(abc.ABC):
    """Base class for all anomaly detection models"""
    
    def __init__(self, config: Union[Dict[str, Any], ModelConfig]):
        """
        Initialize the model with configuration
        
        Args:
            config: Model configuration
        """
        if isinstance(config, dict):
            self.config = ModelConfig(config)
        else:
            self.config = config
            
        # Validate configuration
        is_valid, error_message = self.config.validate()
        if not is_valid:
            raise ValueError(f"Invalid configuration: {error_message}")
            
        self.trained = False
        self.model_path = None
        self.training_stats = {}
        self.feature_names = self.config.feature_names
        self.threshold = self.config.threshold
        
        # Additional metadata
        self.created_at = time.time()
        self.last_updated = self.created_at
        self.version = self.config.version
        
        # Preprocessing functions
        self._preprocessors = []
        
        # Generate a unique ID if not provided
        if not hasattr(self.config, 'model_id') or not self.config.model_id:
            self.config.model_id = f"{self.config.model_type}_{uuid.uuid4().hex[:8]}"
        
    @abc.abstractmethod
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        """
        Train the model on data
        
        Args:
            X: Training data features
            y: Optional training data labels (for supervised models)
        """
        pass
        
    @abc.abstractmethod
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores for data
        
        Args:
            X: Data to score
            
        Returns:
            Array of anomaly scores (higher = more anomalous)
        """
        pass
        
    @abc.abstractmethod
    def predict_with_explanation(self, X: np.ndarray) -> Tuple[np.ndarray, List[Dict[str, float]]]:
        """
        Predict anomaly scores and provide explanations
        
        Args:
            X: Data to score
            
        Returns:
            Tuple of (scores, explanations)
            - scores: Array of anomaly scores
            - explanations: List of dictionaries mapping feature names to importance
        """
        pass
    
    def fit_predict(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> np.ndarray:
        """
        Train model and generate predictions in one step
        
        Args:
            X: Training data
            y: Optional labels
            
        Returns:
            Array of anomaly scores
        """
        self.train(X, y)
        return self.predict(X)
        
    def preprocess(self, X: np.ndarray) -> np.ndarray:
        """
        Apply preprocessing steps to input data
        
        Args:
            X: Input data
            
        Returns:
            Preprocessed data
        """
        processed_X = X.copy()
        for preprocessor in self._preprocessors:
            processed_X = preprocessor(processed_X)
        return processed_X
        
    def add_preprocessor(self, preprocessor: Callable[[np.ndarray], np.ndarray]) -> None:
        """
        Add a preprocessing function to the pipeline
        
        Args:
            preprocessor: Function that takes and returns numpy array
        """
        self._preprocessors.append(preprocessor)
        
    def evaluate(self, X: np.ndarray, y_true: np.ndarray) -> Dict[str, float]:
        """
        Evaluate model performance
        
        Args:
            X: Test data features
            y_true: True binary labels (1 for anomaly, 0 for normal)
            
        Returns:
            Dictionary with evaluation metrics
        """
        # Get anomaly scores
        anomaly_scores = self.predict(X)
        
        # Apply threshold to get predictions
        y_pred = (anomaly_scores >= self.threshold).astype(int)
        
        # Calculate metrics
        tp = np.sum((y_pred == 1) & (y_true == 1))
        fp = np.sum((y_pred == 1) & (y_true == 0))
        tn = np.sum((y_pred == 0) & (y_true == 0))
        fn = np.sum((y_pred == 0) & (y_true == 1))
        
        # Compute common metrics
        accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        # Compute ROC AUC if scikit-learn is available
        auc_roc = None
        try:
            from sklearn.metrics import roc_auc_score
            auc_roc = roc_auc_score(y_true, anomaly_scores)
        except ImportError:
            pass
        
        metrics = {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "true_positives": int(tp),
            "false_positives": int(fp),
            "true_negatives": int(tn),
            "false_negatives": int(fn)
        }
        
        if auc_roc is not None:
            metrics["auc_roc"] = float(auc_roc)
            
        return metrics
        
    def find_optimal_threshold(self, X: np.ndarray, y_true: np.ndarray, 
                              metric: str = 'f1_score', resolution: int = 100) -> float:
        """
        Find optimal threshold based on a metric
        
        Args:
            X: Validation data features
            y_true: True binary labels
            metric: Metric to optimize ('f1_score', 'precision', 'recall', etc.)
            resolution: Number of threshold values to test
            
        Returns:
            Optimal threshold value
        """
        # Get anomaly scores
        anomaly_scores = self.predict(X)
        
        # Define thresholds to test
        thresholds = np.linspace(0, 1, resolution)
        
        best_score = -1
        best_threshold = self.threshold
        
        for threshold in thresholds:
            # Apply threshold
            y_pred = (anomaly_scores >= threshold).astype(int)
            
            # Calculate metrics
            tp = np.sum((y_pred == 1) & (y_true == 1))
            fp = np.sum((y_pred == 1) & (y_true == 0))
            tn = np.sum((y_pred == 0) & (y_true == 0))
            fn = np.sum((y_pred == 0) & (y_true == 1))
            
            # Calculate specific metric
            score = 0
            if metric == 'accuracy':
                score = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
            elif metric == 'precision':
                score = tp / (tp + fp) if (tp + fp) > 0 else 0
            elif metric == 'recall':
                score = tp / (tp + fn) if (tp + fn) > 0 else 0
            elif metric == 'f1_score':
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            # Update best if improved
            if score > best_score:
                best_score = score
                best_threshold = threshold
                
        return best_threshold
    
    def save(self, path: str) -> str:
        """
        Save model to disk
        
        Args:
            path: Directory path to save model
            
        Returns:
            Full path to saved model
        """
        os.makedirs(path, exist_ok=True)
        
        # Update last updated time
        self.last_updated = time.time()
        
        # Save configuration
        config_path = os.path.join(path, "config.json")
        with open(config_path, "w") as f:
            f.write(self.config.to_json())
            
        # Save model metadata
        metadata = {
            "trained": self.trained,
            "threshold": self.threshold,
            "training_stats": self.training_stats,
            "feature_names": self.feature_names,
            "model_type": self.config.model_type,
            "saved_at": time.time(),
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "version": self.version
        }
        
        metadata_path = os.path.join(path, "metadata.json")
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
            
        # Save preprocessing functions
        if self._preprocessors:
            preprocessors_path = os.path.join(path, "preprocessors.pkl")
            with open(preprocessors_path, "wb") as f:
                pickle.dump(self._preprocessors, f)
            
        # Save model-specific data (to be implemented by subclasses)
        model_path = self._save_model_data(path)
        self.model_path = model_path
        
        logger.info(f"Model {self.config.model_id} saved to {path}")
        
        return model_path
    
    @abc.abstractmethod
    def _save_model_data(self, path: str) -> str:
        """
        Save model-specific data to disk
        
        Args:
            path: Directory path to save model data
            
        Returns:
            Path to saved model data
        """
        pass
        
    @classmethod
    @abc.abstractmethod
    def load(cls, path: str) -> 'BaseModel':
        """
        Load model from disk
        
        Args:
            path: Path to saved model
            
        Returns:
            Loaded model instance
        """
        pass
    
    @classmethod
    def load_metadata(cls, path: str) -> Dict[str, Any]:
        """
        Load only the metadata without loading the full model
        
        Args:
            path: Path to saved model directory
            
        Returns:
            Dictionary with model metadata
        """
        metadata_path = os.path.join(path, "metadata.json")
        config_path = os.path.join(path, "config.json")
        
        metadata = {}
        
        # Load metadata if exists
        if os.path.exists(metadata_path):
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                
        # Load config if exists
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                config = json.load(f)
                metadata["config"] = config
                
        return metadata
        
    def get_threshold(self) -> float:
        """Get current anomaly threshold"""
        return self.threshold
        
    def set_threshold(self, threshold: float) -> None:
        """Set anomaly threshold"""
        if not 0 <= threshold <= 1:
            raise ValueError(f"Threshold must be between 0 and 1, got {threshold}")
        self.threshold = threshold
        
    def get_feature_names(self) -> List[str]:
        """Get feature names used by the model"""
        return self.feature_names
    
    def set_feature_names(self, feature_names: List[str]) -> None:
        """Set feature names"""
        self.feature_names = feature_names
        
    def get_training_stats(self) -> Dict[str, Any]:
        """Get model training statistics"""
        return self.training_stats
        
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        return {
            "model_type": self.config.model_type,
            "model_id": self.config.model_id,
            "version": self.version,
            "trained": self.trained,
            "threshold": self.threshold,
            "feature_count": len(self.feature_names),
            "training_stats": self.training_stats,
            "created_at": datetime.fromtimestamp(self.created_at).isoformat(),
            "last_updated": datetime.fromtimestamp(self.last_updated).isoformat(),
            "description": self.config.description,
            "tags": self.config.tags
        }
    
    def process_batch(self, X: np.ndarray, batch_size: int = 1000) -> List[np.ndarray]:
        """
        Process data in batches to avoid memory issues
        
        Args:
            X: Input data
            batch_size: Size of batches
            
        Returns:
            List of prediction arrays
        """
        results = []
        for i in range(0, len(X), batch_size):
            batch = X[i:i + batch_size]
            batch_result = self.predict(batch)
            results.append(batch_result)
            
        return results


class ModelVersioner:
    """Helper class for model versioning"""
    
    @staticmethod
    def increment_version(version: str, level: str = 'patch') -> str:
        """
        Increment semantic version
        
        Args:
            version: Version string in format "major.minor.patch"
            level: Which level to increment ('major', 'minor', or 'patch')
            
        Returns:
            Updated version string
        """
        try:
            major, minor, patch = map(int, version.split('.'))
            
            if level == 'major':
                major += 1
                minor = 0
                patch = 0
            elif level == 'minor':
                minor += 1
                patch = 0
            else:  # patch
                patch += 1
                
            return f"{major}.{minor}.{patch}"
        except ValueError:
            # If version is not in correct format, return incremented patch
            return f"{version}.1"
    
    @staticmethod
    def is_newer_version(version1: str, version2: str) -> bool:
        """
        Check if version1 is newer than version2
        
        Args:
            version1: First version string
            version2: Second version string
            
        Returns:
            True if version1 > version2
        """
        try:
            major1, minor1, patch1 = map(int, version1.split('.'))
            major2, minor2, patch2 = map(int, version2.split('.'))
            
            if major1 > major2:
                return True
            if major1 < major2:
                return False
                
            if minor1 > minor2:
                return True
            if minor1 < minor2:
                return False
                
            return patch1 > patch2
        except ValueError:
            # If versions can't be compared properly, use string comparison
            return version1 > version2
