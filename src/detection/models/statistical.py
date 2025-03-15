"""
Statistical anomaly detection models

Implements z-score, MAD (Median Absolute Deviation),
and other statistical methods for anomaly detection

Version: 1.0.0
Last updated: 2025-03-15 18:31:40
Last updated by: Mritunjay-mj
"""

import numpy as np
import pandas as pd
import pickle
import os
import json
import time
import warnings
from typing import Dict, Any, List, Tuple, Optional, Union, Literal
from pathlib import Path
from scipy import stats

from src.detection.models.base import BaseModel, ModelConfig
from src.common.logging_config import get_logger

# Initialize logger
logger = get_logger("asira.detection.models.statistical")

class StatisticalModel(BaseModel):
    """
    Statistical anomaly detection model using z-scores and MAD
    
    Uses both standard deviation and median absolute deviation
    for robust anomaly detection.
    """
    
    def __init__(self, config: Union[Dict[str, Any], ModelConfig]):
        """
        Initialize statistical model
        
        Args:
            config: Model configuration
        """
        if isinstance(config, dict):
            config["model_type"] = "statistical"
            
        super().__init__(config)
        
        # Statistical parameters
        self.mean = None
        self.std = None
        self.median = None
        self.mad = None  # Median Absolute Deviation
        self.q1 = None   # First quartile (25%)
        self.q3 = None   # Third quartile (75%)
        self.iqr = None  # Interquartile Range
        
        # Detection methods and their weights
        self.methods = self.config.config.get("methods", ["zscore", "mad"])
        self.method_weights = self.config.config.get("method_weights", {
            "zscore": 1.0,
            "mad": 1.0,
            "iqr": 0.0,  # Disabled by default
            "robust": 0.0  # Disabled by default
        })
        
        # Thresholds for different methods
        self.z_score_threshold = self.config.config.get("z_score_threshold", 3.0)
        self.mad_threshold = self.config.config.get("mad_threshold", 3.0)
        self.iqr_threshold = self.config.config.get("iqr_threshold", 1.5)
        
        # Normalization constants for MAD (assuming normal distribution)
        self.mad_normalization_constant = 1.4826  # for normal distribution
        
        # For batch processing
        self.batch_size = self.config.config.get("batch_size", 10000)
        
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        """
        Calculate statistical parameters from training data
        
        Args:
            X: Training data
            y: Ignored for unsupervised model
        """
        if X.shape[0] == 0:
            raise ValueError("Cannot train on empty dataset")
            
        start_time = time.time()
        
        # Calculate standard statistics
        self.mean = np.mean(X, axis=0)
        self.std = np.std(X, axis=0)
        
        # Handle zero standard deviation
        self.std = np.where(self.std < 1e-10, 1e-10, self.std)
        
        # Calculate robust statistics
        self.median = np.median(X, axis=0)
        # MAD = median(|X - median(X)|)
        self.mad = np.median(np.abs(X - self.median), axis=0) * self.mad_normalization_constant
        
        # Handle zero MAD
        self.mad = np.where(self.mad < 1e-10, 1e-10, self.mad)
        
        # Calculate IQR statistics
        self.q1 = np.percentile(X, 25, axis=0)
        self.q3 = np.percentile(X, 75, axis=0)
        self.iqr = self.q3 - self.q1
        
        # Handle zero IQR
        self.iqr = np.where(self.iqr < 1e-10, 1e-10, self.iqr)
        
        # Find optimal thresholds if requested
        if self.config.config.get("auto_threshold", False) and y is not None:
            try:
                # Try to find optimal z-score threshold
                best_f1 = 0
                best_threshold = self.z_score_threshold
                
                # Get z-scores
                z_scores = np.abs((X - self.mean) / self.std)
                z_scores_mean = np.mean(z_scores, axis=1)
                
                # Try different thresholds
                for threshold in np.linspace(1.0, 5.0, 41):  # Try from 1.0 to 5.0
                    predictions = (z_scores_mean > threshold).astype(int)
                    tp = np.sum(predictions & y)
                    fp = np.sum(predictions & ~y)
                    fn = np.sum(~predictions & y)
                    
                    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                    
                    if f1 > best_f1:
                        best_f1 = f1
                        best_threshold = threshold
                
                self.z_score_threshold = best_threshold
                logger.info(f"Auto-selected z-score threshold: {self.z_score_threshold}")
                
                # Similar for MAD threshold
                best_f1 = 0
                best_threshold = self.mad_threshold
                
                # Get MAD scores
                mad_scores = np.abs((X - self.median) / self.mad)
                mad_scores_mean = np.mean(mad_scores, axis=1)
                
                # Try different thresholds
                for threshold in np.linspace(1.0, 5.0, 41):  # Try from 1.0 to 5.0
                    predictions = (mad_scores_mean > threshold).astype(int)
                    tp = np.sum(predictions & y)
                    fp = np.sum(predictions & ~y)
                    fn = np.sum(~predictions & y)
                    
                    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                    
                    if f1 > best_f1:
                        best_f1 = f1
                        best_threshold = threshold
                
                self.mad_threshold = best_threshold
                logger.info(f"Auto-selected MAD threshold: {self.mad_threshold}")
                
            except Exception as e:
                logger.warning(f"Error auto-selecting thresholds: {e}")
        
        # Record training stats
        self.training_stats = {
            "n_samples": X.shape[0],
            "n_features": X.shape[1],
            "training_time": time.time() - start_time,
            "z_score_threshold": self.z_score_threshold,
            "mad_threshold": self.mad_threshold,
            "iqr_threshold": self.iqr_threshold,
        }
        
        self.trained = True
        logger.info(f"Statistical model trained on {X.shape[0]} samples, {X.shape[1]} features")
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Calculate anomaly scores based on statistical measures
        
        Args:
            X: Data to score
            
        Returns:
            Array of anomaly scores where higher values are more anomalous
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
        
        # For large datasets, process in batches
        if X.shape[0] > self.batch_size:
            return self._predict_batched(X)
            
        # Apply preprocessing
        X = self.preprocess(X)
        
        # Calculate scores using different methods
        scores_dict = {}
        weights_sum = 0
        
        # Z-score calculation (standard)
        if self.method_weights.get("zscore", 0) > 0:
            z_scores = np.abs((X - self.mean) / self.std)
            z_scores_mean = np.mean(z_scores, axis=1)
            scores_dict["zscore"] = z_scores_mean
            weights_sum += self.method_weights["zscore"]
        
        # MAD calculation (robust)
        if self.method_weights.get("mad", 0) > 0:
            mad_scores = np.abs((X - self.median) / self.mad)
            mad_scores_mean = np.mean(mad_scores, axis=1)
            scores_dict["mad"] = mad_scores_mean
            weights_sum += self.method_weights["mad"]
            
        # IQR calculation
        if self.method_weights.get("iqr", 0) > 0:
            # Calculate how far outside the IQR each point is
            lower_bound = self.q1 - self.iqr_threshold * self.iqr
            upper_bound = self.q3 + self.iqr_threshold * self.iqr
            
            # Calculate distance from bounds (0 if within bounds)
            lower_distance = np.maximum(0, (lower_bound - X) / self.iqr)
            upper_distance = np.maximum(0, (X - upper_bound) / self.iqr)
            
            # Take maximum distance for each feature
            iqr_scores = np.maximum(lower_distance, upper_distance)
            iqr_scores_mean = np.mean(iqr_scores, axis=1)
            
            scores_dict["iqr"] = iqr_scores_mean
            weights_sum += self.method_weights["iqr"]
            
        # Robust tests (e.g., Grubbs test for outliers)
        if self.method_weights.get("robust", 0) > 0:
            # Simple robust calculation - based on modified Z-score
            modified_z_scores = np.abs(0.6745 * (X - self.median) / self.mad)
            robust_scores_mean = np.mean(modified_z_scores, axis=1)
            
            scores_dict["robust"] = robust_scores_mean
            weights_sum += self.method_weights["robust"]
        
        # Ensure we have at least one method
        if not scores_dict:
            logger.warning("No statistical methods enabled, using Z-score")
            z_scores = np.abs((X - self.mean) / self.std)
            z_scores_mean = np.mean(z_scores, axis=1)
            scores_dict["zscore"] = z_scores_mean
            weights_sum = 1.0
        
        # Combine scores with weights
        combined_scores = np.zeros(X.shape[0])
        for method, scores in scores_dict.items():
            weight = self.method_weights.get(method, 0)
            combined_scores += scores * weight
            
        # Normalize by sum of weights
        if weights_sum > 0:
            combined_scores /= weights_sum
        
        # Normalize to [0, 1] range
        max_score = np.max(combined_scores) if len(combined_scores) > 0 else 1.0
        normalized_scores = combined_scores / max(max_score, 1e-10)
        
        return normalized_scores
    
    def _predict_batched(self, X: np.ndarray) -> np.ndarray:
        """
        Process large datasets in batches
        
        Args:
            X: Data to score
            
        Returns:
            Array of anomaly scores
        """
        results = []
        
        for i in range(0, X.shape[0], self.batch_size):
            batch = X[i:i+self.batch_size]
            batch_scores = self.predict(batch)
            results.append(batch_scores)
            
        return np.concatenate(results)
        
    def predict_with_explanation(self, X: np.ndarray) -> Tuple[np.ndarray, List[Dict[str, float]]]:
        """
        Get anomaly scores with feature importance explanations
        
        Args:
            X: Data to score
            
        Returns:
            Tuple of (scores, explanations)
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Apply preprocessing
        X = self.preprocess(X)
        
        # Get anomaly scores
        anomaly_scores = self.predict(X)
        
        # Calculate feature-wise deviations for explanation
        z_scores = np.abs((X - self.mean) / self.std)
        mad_scores = np.abs((X - self.median) / self.mad)
        
        # Calculate IQR-based scores if enabled
        if self.method_weights.get("iqr", 0) > 0:
            lower_bound = self.q1 - self.iqr_threshold * self.iqr
            upper_bound = self.q3 + self.iqr_threshold * self.iqr
            lower_distance = np.maximum(0, (lower_bound - X) / self.iqr)
            upper_distance = np.maximum(0, (X - upper_bound) / self.iqr)
            iqr_scores = np.maximum(lower_distance, upper_distance)
        else:
            iqr_scores = np.zeros_like(X)
        
        # Generate explanations
        explanations = []
        for i in range(X.shape[0]):
            # Calculate feature importance for this sample
            # by averaging feature contributions across methods
            feature_scores = {}
            
            # Track weighted sum of scores for each feature
            weighted_feature_scores = np.zeros(X.shape[1])
            weights_sum = 0
            
            # Z-score contribution
            if self.method_weights.get("zscore", 0) > 0:
                z_weight = self.method_weights["zscore"]
                z_sum = np.sum(z_scores[i])
                
                if z_sum > 0:
                    weighted_feature_scores += (z_scores[i] / z_sum) * z_weight
                weights_sum += z_weight
                
            # MAD contribution
            if self.method_weights.get("mad", 0) > 0:
                mad_weight = self.method_weights["mad"]
                mad_sum = np.sum(mad_scores[i])
                
                if mad_sum > 0:
                    weighted_feature_scores += (mad_scores[i] / mad_sum) * mad_weight
                weights_sum += mad_weight
                
            # IQR contribution
            if self.method_weights.get("iqr", 0) > 0:
                iqr_weight = self.method_weights["iqr"]
                iqr_sum = np.sum(iqr_scores[i])
                
                if iqr_sum > 0:
                    weighted_feature_scores += (iqr_scores[i] / iqr_sum) * iqr_weight
                weights_sum += iqr_weight
            
            # Normalize by sum of weights
            if weights_sum > 0:
                weighted_feature_scores /= weights_sum
            else:
                # Equal importance if no weights assigned
                weighted_feature_scores = np.ones(X.shape[1]) / X.shape[1]
                
            # Create feature importance dictionary
            for j in range(X.shape[1]):
                feature_name = self.feature_names[j] if j < len(self.feature_names) else f"feature_{j}"
                feature_scores[feature_name] = float(weighted_feature_scores[j])
            
            explanations.append(feature_scores)
            
        return anomaly_scores, explanations
    
    def get_top_anomalous_features(self, X: np.ndarray, top_n: int = 3) -> List[List[Tuple[str, float]]]:
        """
        Get top N most anomalous features for each data point
        
        Args:
            X: Data to analyze
            top_n: Number of top features to return
            
        Returns:
            List of lists of (feature_name, score) tuples
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Apply preprocessing
        X = self.preprocess(X)
        
        # Calculate feature-wise deviations
        z_scores = np.abs((X - self.mean) / self.std)
        mad_scores = np.abs((X - self.median) / self.mad)
        
        # Combine scores (use same weights as in prediction)
        feature_scores = np.zeros_like(X)
        weights_sum = 0
        
        if self.method_weights.get("zscore", 0) > 0:
            feature_scores += z_scores * self.method_weights["zscore"]
            weights_sum += self.method_weights["zscore"]
            
        if self.method_weights.get("mad", 0) > 0:
            feature_scores += mad_scores * self.method_weights["mad"]
            weights_sum += self.method_weights["mad"]
            
        # IQR-based scores if enabled
        if self.method_weights.get("iqr", 0) > 0:
            lower_bound = self.q1 - self.iqr_threshold * self.iqr
            upper_bound = self.q3 + self.iqr_threshold * self.iqr
            lower_distance = np.maximum(0, (lower_bound - X) / self.iqr)
            upper_distance = np.maximum(0, (X - upper_bound) / self.iqr)
            iqr_scores = np.maximum(lower_distance, upper_distance)
            
            feature_scores += iqr_scores * self.method_weights["iqr"]
            weights_sum += self.method_weights["iqr"]
            
        # Normalize
        if weights_sum > 0:
            feature_scores /= weights_sum
        
        # Get top features for each sample
        result = []
        for i in range(X.shape[0]):
            sample_scores = feature_scores[i]
            
            # Get indices of top_n highest scores
            top_indices = np.argsort(sample_scores)[-top_n:][::-1]
            
            # Create list of (feature_name, score) tuples
            top_features = []
            for idx in top_indices:
                feature_name = self.feature_names[idx] if idx < len(self.feature_names) else f"feature_{idx}"
                top_features.append((feature_name, float(sample_scores[idx])))
                
            result.append(top_features)
            
        return result
    
    def calculate_feature_thresholds(self, X: np.ndarray, method: str = 'zscore', 
                                    threshold_multiplier: float = 3.0) -> Dict[str, Dict[str, float]]:
        """
        Calculate per-feature thresholds for anomaly detection
        
        Args:
            X: Training data
            method: Method to use ('zscore', 'mad', or 'iqr')
            threshold_multiplier: Multiplier for thresholds
            
        Returns:
            Dictionary with lower and upper bounds for each feature
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Apply preprocessing
        X = self.preprocess(X)
        
        result = {}
        
        for j in range(X.shape[1]):
            feature_name = self.feature_names[j] if j < len(self.feature_names) else f"feature_{j}"
            
            if method == 'zscore':
                # Z-score thresholds
                mean = self.mean[j]
                std = self.std[j]
                lower = mean - threshold_multiplier * std
                upper = mean + threshold_multiplier * std
                
                result[feature_name] = {
                    "lower": float(lower),
                    "upper": float(upper),
                    "mean": float(mean),
                    "std": float(std)
                }
                
            elif method == 'mad':
                # MAD thresholds
                median = self.median[j]
                mad = self.mad[j]
                lower = median - threshold_multiplier * mad
                upper = median + threshold_multiplier * mad
                
                result[feature_name] = {
                    "lower": float(lower),
                    "upper": float(upper),
                    "median": float(median),
                    "mad": float(mad)
                }
                
            elif method == 'iqr':
                # IQR thresholds
                q1 = self.q1[j]
                q3 = self.q3[j]
                iqr = self.iqr[j]
                lower = q1 - threshold_multiplier * iqr
                upper = q3 + threshold_multiplier * iqr
                
                result[feature_name] = {
                    "lower": float(lower),
                    "upper": float(upper),
                    "q1": float(q1),
                    "q3": float(q3),
                    "iqr": float(iqr)
                }
                
            else:
                raise ValueError(f"Unknown method: {method}")
                
        return result
    
    def analyze_feature_distribution(self, X: np.ndarray, feature_index: int) -> Dict[str, Any]:
        """
        Analyze distribution characteristics of a specific feature
        
        Args:
            X: Data to analyze
            feature_index: Index of feature to analyze
            
        Returns:
            Dictionary with distribution characteristics
        """
        if feature_index < 0 or feature_index >= X.shape[1]:
            raise ValueError(f"Invalid feature index: {feature_index}. Must be between 0 and {X.shape[1]-1}")
            
        # Extract feature values
        values = X[:, feature_index]
        
        # Basic statistics
        mean = np.mean(values)
        median = np.median(values)
        std = np.std(values)
        min_val = np.min(values)
        max_val = np.max(values)
        
        # Percentiles
        p25 = np.percentile(values, 25)
        p75 = np.percentile(values, 75)
        iqr = p75 - p25
        
        # Check for normality (Shapiro-Wilk test)
        normality_test = None
        try:
            # Only test a sample if there are too many values
            if len(values) > 5000:
                test_values = np.random.choice(values, 5000, replace=False)
            else:
                test_values = values
                
            shapiro_stat, shapiro_p = stats.shapiro(test_values)
            normality_test = {
                "test": "shapiro",
                "statistic": float(shapiro_stat),
                "p_value": float(shapiro_p),
                "is_normal": shapiro_p > 0.05
            }
        except Exception:
            pass
        
        # Get feature name
        feature_name = self.feature_names[feature_index] if feature_index < len(self.feature_names) else f"feature_{feature_index}"
        
        return {
            "feature_name": feature_name,
            "feature_index": feature_index,
            "mean": float(mean),
            "median": float(median),
            "std": float(std),
            "min": float(min_val),
            "max": float(max_val),
            "p25": float(p25),
            "p75": float(p75),
            "iqr": float(iqr),
            "skewness": float(stats.skew(values)),
            "kurtosis": float(stats.kurtosis(values)),
            "normality_test": normality_test
        }
    
    def _save_model_data(self, path: str) -> str:
        """
        Save model data to disk
        
        Args:
            path: Directory path
            
        Returns:
            Path to saved model file
        """
        model_data = {
            "mean": self.mean,
            "std": self.std,
            "median": self.median,
            "mad": self.mad,
            "q1": self.q1,
            "q3": self.q3,
            "iqr": self.iqr,
            "z_score_threshold": self.z_score_threshold,
            "mad_threshold": self.mad_threshold,
            "iqr_threshold": self.iqr_threshold,
            "methods": self.methods,
            "method_weights": self.method_weights
        }
        
        # Convert numpy arrays to lists for JSON serialization
        model_dict = {
            "mean": model_data["mean"].tolist() if model_data["mean"] is not None else None,
            "std": model_data["std"].tolist() if model_data["std"] is not None else None,
            "median": model_data["median"].tolist() if model_data["median"] is not None else None,
            "mad": model_data["mad"].tolist() if model_data["mad"] is not None else None,
            "q1": model_data["q1"].tolist() if model_data["q1"] is not None else None,
            "q3": model_data["q3"].tolist() if model_data["q3"] is not None else None,
            "iqr": model_data["iqr"].tolist() if model_data["iqr"] is not None else None,
            "z_score_threshold": model_data["z_score_threshold"],
            "mad_threshold": model_data["mad_threshold"],
            "iqr_threshold": model_data["iqr_threshold"],
            "methods": model_data["methods"],
            "method_weights": model_data["method_weights"]
        }
        
        model_path = os.path.join(path, "statistical_model.json")
        with open(model_path, "w") as f:
            json.dump(model_dict, f, indent=2)
            
        return model_path
        
    @classmethod
    def load(cls, path: str) -> 'StatisticalModel':
        """
        Load model from disk
        
        Args:
            path: Path to model directory
            
        Returns:
            Loaded model
        """
        # Load configuration
        config_path = os.path.join(path, "config.json")
        with open(config_path, "r") as f:
            config = ModelConfig.from_json(f.read())
            
        # Create model instance
        model = cls(config)
        
        # Load model data
        model_path = os.path.join(path, "statistical_model.json")
        with open(model_path, "r") as f:
            model_dict = json.load(f)
            
        # Convert lists back to numpy arrays
        model.mean = np.array(model_dict["mean"]) if model_dict["mean"] is not None else None
        model.std = np.array(model_dict["std"]) if model_dict["std"] is not None else None
        model.median = np.array(model_dict["median"]) if model_dict["median"] is not None else None
        model.mad = np.array(model_dict["mad"]) if model_dict["mad"] is not None else None
        
        # Load IQR related fields if they exist
        if "q1" in model_dict and model_dict["q1"] is not None:
            model.q1 = np.array(model_dict["q1"])
        if "q3" in model_dict and model_dict["q3"] is not None:
            model.q3 = np.array(model_dict["q3"])
        if "iqr" in model_dict and model_dict["iqr"] is not None:
            model.iqr = np.array(model_dict["iqr"])
        
        # Load thresholds
        model.z_score_threshold = model_dict["z_score_threshold"]
        model.mad_threshold = model_dict["mad_threshold"]
        
        if "iqr_threshold" in model_dict:
            model.iqr_threshold = model_dict["iqr_threshold"]
            
        # Load methods and weights
        if "methods" in model_dict:
            model.methods = model_dict["methods"]
        if "method_weights" in model_dict:
            model.method_weights = model_dict["method_weights"]
        
        # Load metadata
        metadata_path = os.path.join(path, "metadata.json")
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
            
        model.trained = metadata["trained"]
        model.threshold = metadata["threshold"]
        model.training_stats = metadata["training_stats"]
        model.feature_names = metadata["feature_names"]
        
        # Load preprocessors if they exist
        preprocessors_path = os.path.join(path, "preprocessors.pkl")
        if os.path.exists(preprocessors_path):
            with open(preprocessors_path, "rb") as f:
                model._preprocessors = pickle.load(f)
        
        return model
    
    def to_std_scaler(self) -> Any:
        """
        Convert to scikit-learn StandardScaler
        
        Returns:
            StandardScaler object
        """
        try:
            from sklearn.preprocessing import StandardScaler
            scaler = StandardScaler()
            scaler.mean_ = self.mean
            scaler.scale_ = self.std
            scaler.var_ = self.std ** 2
            scaler.n_features_in_ = len(self.mean)
            return scaler
        except ImportError:
            logger.warning("sklearn not available, cannot create StandardScaler")
            return None


# Create utility methods for common statistical tests
def is_outlier_zscore(value: float, mean: float, std: float, threshold: float = 3.0) -> bool:
    """
    Check if value is an outlier based on z-score
    
    Args:
        value: Value to check
        mean: Mean of the distribution
        std: Standard deviation of the distribution
        threshold: Z-score threshold (default: 3.0)
        
    Returns:
        True if value is an outlier
    """
    if std < 1e-10:  # Avoid division by zero
        return False
    z_score = abs((value - mean) / std)
    return z_score > threshold


def is_outlier_mad(value: float, median: float, mad: float, threshold: float = 3.0) -> bool:
    """
    Check if value is an outlier based on Median Absolute Deviation
    
    Args:
        value: Value to check
        median: Median of the distribution
        mad: Median Absolute Deviation
        threshold: MAD threshold (default: 3.0)
        
    Returns:
        True if value is an outlier
    """
    if mad < 1e-10:  # Avoid division by zero
        return False
    # Use normalization constant for normal distribution
    modified_z_score = 0.6745 * abs(value - median) / mad
    return modified_z_score > threshold


def is_outlier_iqr(value: float, q1: float, q3: float, threshold: float = 1.5) -> bool:
    """
    Check if value is an outlier based on IQR
    
    Args:
        value: Value to check
        q1: First quartile (25%)
        q3: Third quartile (75%)
        threshold: IQR multiplier (default: 1.5)
        
    Returns:
        True if value is an outlier
    """
    iqr = q3 - q1
    if iqr < 1e-10:  # Avoid division by zero
        return False
    lower_bound = q1 - threshold * iqr
    upper_bound = q3 + threshold * iqr
    return value < lower_bound or value > upper_bound


def calculate_feature_importance(anomaly_scores: np.ndarray, feature_scores: np.ndarray) -> np.ndarray:
    """
    Calculate feature importance for anomalous samples
    
    Args:
        anomaly_scores: Overall anomaly scores for samples
        feature_scores: Feature-level anomaly scores
        
    Returns:
        Array of feature importance values
    """
    # Compute correlation between feature scores and overall anomaly scores
    importance = np.zeros(feature_scores.shape[1])
    
    for j in range(feature_scores.shape[1]):
        # Compute correlation coefficient
        corr = np.corrcoef(anomaly_scores, feature_scores[:, j])[0, 1]
        importance[j] = abs(corr)  # Take absolute value
    
    # Normalize to sum to 1.0
    if np.sum(importance) > 0:
        importance = importance / np.sum(importance)
        
    return importance


def find_optimal_threshold(scores: np.ndarray, labels: np.ndarray) -> Tuple[float, Dict[str, float]]:
    """
    Find the optimal threshold for anomaly detection
    
    Args:
        scores: Anomaly scores
        labels: True labels (1 for anomaly, 0 for normal)
        
    Returns:
        Tuple of (optimal_threshold, metrics_dict)
    """
    best_f1 = -1
    best_threshold = 0
    best_metrics = {}
    
    # Try different thresholds
    thresholds = np.linspace(0.01, 0.99, 99)
    
    for threshold in thresholds:
        predictions = (scores >= threshold).astype(int)
        
        # Calculate metrics
        tp = np.sum((predictions == 1) & (labels == 1))
        fp = np.sum((predictions == 1) & (labels == 0))
        tn = np.sum((predictions == 0) & (labels == 0))
        fn = np.sum((predictions == 0) & (labels == 1))
        
        # Calculate derived metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
        
        # Update best threshold
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = threshold
            best_metrics = {
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
                "accuracy": float(accuracy),
                "true_positives": int(tp),
                "false_positives": int(fp),
                "true_negatives": int(tn),
                "false_negatives": int(fn)
            }
    
    return best_threshold, best_metrics


# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 18:31:15"
__author__ = "Mritunjay-mj"
