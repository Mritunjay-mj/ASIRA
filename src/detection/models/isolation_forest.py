"""
Isolation Forest anomaly detection model

Implements Isolation Forest algorithm for anomaly detection
using scikit-learn as the backend

Version: 1.0.0
Last updated: 2025-03-15 18:35:32
Last updated by: Rahul
"""

import numpy as np
import pandas as pd
import pickle
import os
import json
import time
import warnings
from typing import Dict, Any, List, Tuple, Optional, Union, Callable
from pathlib import Path

# Scikit-learn imports
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError
from sklearn.preprocessing import StandardScaler

from src.detection.models.base import BaseModel, ModelConfig
from src.common.logging_config import get_logger

# Initialize logger
logger = get_logger("asira.detection.models.isolation_forest")

class IsolationForestModel(BaseModel):
    """
    Isolation Forest model for anomaly detection
    
    Isolation Forest isolates observations by randomly selecting a feature
    and then randomly selecting a split value between the maximum and
    minimum values of the selected feature.
    """
    
    def __init__(self, config: Union[Dict[str, Any], ModelConfig]):
        """
        Initialize Isolation Forest model
        
        Args:
            config: Model configuration
        """
        if isinstance(config, dict):
            config["model_type"] = "isolation_forest"
            
        super().__init__(config)
        
        # Extract isolation forest parameters from config
        self.n_estimators = self.config.config.get("n_estimators", 100)
        self.max_samples = self.config.config.get("max_samples", "auto")
        self.contamination = self.config.config.get("contamination", "auto")
        self.max_features = self.config.config.get("max_features", 1.0)
        self.bootstrap = self.config.config.get("bootstrap", False)
        self.n_jobs = self.config.config.get("n_jobs", -1)
        self.random_state = self.config.config.get("random_state", 42)
        self.batch_size = self.config.config.get("batch_size", 10000)
        
        # Preprocessing options
        self.auto_scale = self.config.config.get("auto_scale", False)
        self.scaler = None
        
        # Feature selection options
        self.feature_selection = self.config.config.get("feature_selection", False)
        self.feature_importance_threshold = self.config.config.get("feature_importance_threshold", 0.01)
        self.selected_features = None
        
        # Create sklearn model
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            max_features=self.max_features,
            bootstrap=self.bootstrap,
            n_jobs=self.n_jobs,
            random_state=self.random_state,
            verbose=0
        )
        
        self.feature_importances_ = None
        self._shap_available = self._check_shap_available()
        
    def _check_shap_available(self) -> bool:
        """Check if SHAP is available for better explanations"""
        try:
            import shap
            return True
        except ImportError:
            return False
        
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        """
        Train the isolation forest model
        
        Args:
            X: Training data
            y: Ignored for unsupervised model
        """
        if X.shape[0] == 0:
            raise ValueError("Cannot train on empty dataset")
            
        start_time = time.time()
        
        # Apply preprocessing if configured
        if self.auto_scale:
            logger.info("Applying automatic scaling to training data")
            self.scaler = StandardScaler()
            X = self.scaler.fit_transform(X)
        
        # Apply preprocessing steps defined in base class
        X = self.preprocess(X)
            
        # Train the model
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            self.model.fit(X)
        
        # Calculate feature importances
        # For Isolation Forest, this is not directly available
        # We'll estimate importances using the mean depth decrease
        if hasattr(self.model, "estimators_"):
            n_samples = X.shape[0]
            n_features = X.shape[1]
            
            # Initialize feature importances array
            self.feature_importances_ = np.zeros(n_features)
            
            # For each tree in the forest
            for tree in self.model.estimators_:
                # Extract the tree structure
                # Each feature used for splitting contributes to importance
                for i, (feature, threshold) in enumerate(zip(tree.feature_, tree.threshold_)):
                    if feature != -2:  # -2 indicates leaf node
                        self.feature_importances_[feature] += 1
                        
            # Normalize importances
            if np.sum(self.feature_importances_) > 0:
                self.feature_importances_ /= np.sum(self.feature_importances_)
        else:
            # If estimators not available, use uniform importances
            self.feature_importances_ = np.ones(X.shape[1]) / X.shape[1]
            
        # Apply feature selection if configured
        if self.feature_selection and self.feature_importance_threshold > 0:
            # Select features with importance above threshold
            self.selected_features = np.where(self.feature_importances_ > self.feature_importance_threshold)[0]
            logger.info(f"Selected {len(self.selected_features)} features with importance above {self.feature_importance_threshold}")
        
        # Record training statistics
        self.training_stats = {
            "n_samples": X.shape[0],
            "n_features": X.shape[1],
            "training_time": time.time() - start_time,
            "feature_importances": {
                self.feature_names[i] if i < len(self.feature_names) else f"feature_{i}": float(imp)
                for i, imp in enumerate(self.feature_importances_) if imp > 0.01
            },
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "contamination": self.contamination
        }
        
        if self.selected_features is not None:
            self.training_stats["selected_features"] = len(self.selected_features)
        
        self.trained = True
        logger.info(f"Isolation Forest model trained on {X.shape[0]} samples, {X.shape[1]} features")
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores using Isolation Forest
        
        Args:
            X: Data to score
            
        Returns:
            Array of anomaly scores (higher = more anomalous)
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # For large datasets, process in batches
        if X.shape[0] > self.batch_size:
            return self._predict_batched(X)
            
        # Apply preprocessing
        X = self._preprocess_prediction_data(X)
            
        try:
            # Get raw scores (-1 to 1, where -1 is anomalous)
            raw_scores = self.model.decision_function(X)
            
            # Convert to anomaly score (0 to 1, where 1 is anomalous)
            # decision_function returns:
            #   - negative values for anomalies (lower = more anomalous)
            #   - positive values for normal samples
            anomaly_scores = 1 - (1 + raw_scores) / 2
            
            return anomaly_scores
            
        except NotFittedError:
            self.trained = False
            raise ValueError("Model not properly fitted. Train the model again.")
    
    def _preprocess_prediction_data(self, X: np.ndarray) -> np.ndarray:
        """Apply all preprocessing steps to prediction data"""
        # Apply scaling if it was used in training
        if self.auto_scale and self.scaler is not None:
            X = self.scaler.transform(X)
        
        # Apply base class preprocessing
        X = self.preprocess(X)
        
        # Apply feature selection if configured
        if self.feature_selection and self.selected_features is not None:
            X = X[:, self.selected_features]
            
        return X
    
    def _predict_batched(self, X: np.ndarray) -> np.ndarray:
        """Process large datasets in batches"""
        results = []
        
        for i in range(0, X.shape[0], self.batch_size):
            batch = X[i:i+self.batch_size]
            batch_scores = self.predict(batch)
            results.append(batch_scores)
            
        return np.concatenate(results)
    
    def predict_labels(self, X: np.ndarray) -> np.ndarray:
        """
        Predict binary labels (1: anomaly, 0: normal)
        
        Args:
            X: Data to predict
            
        Returns:
            Binary labels (1: anomaly, 0: normal)
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Get anomaly scores
        scores = self.predict(X)
        
        # Apply threshold
        return (scores >= self.threshold).astype(int)
        
    def predict_with_explanation(self, X: np.ndarray) -> Tuple[np.ndarray, List[Dict[str, float]]]:
        """
        Predict with feature importance explanations
        
        Args:
            X: Data to score
            
        Returns:
            Tuple of (scores, explanations)
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Apply preprocessing
        X_proc = self._preprocess_prediction_data(X)
        
        # Get anomaly scores
        anomaly_scores = self.predict(X)
        
        # Generate explanations
        explanations = []
        
        # Try to use SHAP if available for better explanations
        if self._shap_available and len(X) < 1000:  # Limit SHAP to smaller datasets due to computational cost
            try:
                import shap
                
                # Create a background dataset for SHAP (sample if too large)
                try:
                    # Get access to internal estimators
                    estimators = self.model.estimators_
                    trees = [e.tree_ for e in estimators]
                    
                    # Create explainer
                    explainer = shap.TreeExplainer(
                        self.model,
                        data=X_proc[:min(100, len(X_proc))],
                        model_output="raw"
                    )
                    
                    # Calculate SHAP values
                    shap_values = explainer.shap_values(X_proc)
                    
                    # Create explanations from SHAP values
                    for i in range(X_proc.shape[0]):
                        feature_scores = {}
                        
                        # Normalize SHAP values to sum to 1 for consistency
                        abs_shap = np.abs(shap_values[i])
                        total = np.sum(abs_shap)
                        
                        if total > 0:
                            normalized_shap = abs_shap / total
                        else:
                            normalized_shap = abs_shap
                        
                        for j in range(X_proc.shape[1]):
                            feature_idx = j
                            # If we used feature selection, map back to original indices
                            if self.selected_features is not None:
                                feature_idx = self.selected_features[j]
                                
                            feature_name = self.feature_names[feature_idx] if feature_idx < len(self.feature_names) else f"feature_{feature_idx}"
                            feature_scores[feature_name] = float(normalized_shap[j])
                            
                        explanations.append(feature_scores)
                        
                    # SHAP explanations created successfully
                    return anomaly_scores, explanations
                    
                except Exception as e:
                    logger.warning(f"Error calculating SHAP values: {e}. Falling back to approximate explanations.")
            except ImportError:
                # SHAP couldn't be imported
                pass
        
        # Fallback: create approximate explanations using global feature importance
        for i in range(X.shape[0]):
            feature_scores = {}
            
            for j in range(X.shape[1]):
                feature_idx = j
                # If we used feature selection, skip features not selected
                if self.selected_features is not None:
                    if j >= len(self.selected_features):
                        continue
                    feature_idx = self.selected_features[j]
                    
                feature_name = self.feature_names[feature_idx] if feature_idx < len(self.feature_names) else f"feature_{feature_idx}"
                
                # Use global feature importance adjusted by the deviation from mean
                # This is an approximation since IF doesn't provide per-sample importances
                if self.feature_importances_ is not None:
                    feature_scores[feature_name] = self.feature_importances_[feature_idx]
                else:
                    feature_scores[feature_name] = 1.0 / X.shape[1]
                
            explanations.append(feature_scores)
            
        return anomaly_scores, explanations
    
    def get_top_anomalies(self, X: np.ndarray, top_n: int = 10) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, float]]]:
        """
        Get the top N most anomalous samples
        
        Args:
            X: Data to analyze
            top_n: Number of top anomalies to return
            
        Returns:
            Tuple of (indices, scores, explanations)
        """
        # Get anomaly scores
        scores = self.predict(X)
        
        # Get indices of top anomalies
        if len(scores) <= top_n:
            # If we have fewer samples than requested top_n
            top_indices = np.argsort(scores)[::-1]
        else:
            top_indices = np.argsort(scores)[-top_n:][::-1]
            
        # Get scores for top anomalies
        top_scores = scores[top_indices]
        
        # Get explanations for top anomalies
        _, explanations = self.predict_with_explanation(X[top_indices])
        
        return top_indices, top_scores, explanations
    
    def optimize_hyperparameters(self, X: np.ndarray, y: Optional[np.ndarray] = None, 
                              param_grid: Optional[Dict[str, List]] = None) -> Dict[str, Any]:
        """
        Optimize hyperparameters using grid search
        
        Args:
            X: Training data
            y: Optional labels for supervised evaluation
            param_grid: Dictionary of parameter grids to search
            
        Returns:
            Best parameters found
        """
        try:
            from sklearn.model_selection import GridSearchCV, KFold
            
            # Default parameter grid if not provided
            if param_grid is None:
                param_grid = {
                    'n_estimators': [50, 100, 200],
                    'max_samples': [100, 256, 'auto'],
                    'contamination': [0.01, 0.05, 0.1],
                    'max_features': [0.5, 0.8, 1.0]
                }
                
            # Create base model for grid search
            base_model = IsolationForest(random_state=self.random_state)
            
            # Prepare evaluation strategy
            if y is not None:
                # If we have labels, use them
                from sklearn.metrics import make_scorer, f1_score
                
                # Custom scorer for anomaly detection
                def anomaly_score(estimator, X_eval):
                    scores = 1 - (1 + estimator.decision_function(X_eval)) / 2
                    preds = (scores >= 0.5).astype(int)
                    return f1_score(y, preds)
                
                scorer = make_scorer(anomaly_score)
                cv = KFold(n_splits=3, shuffle=True, random_state=self.random_state)
                
                # Create GridSearchCV
                grid_search = GridSearchCV(
                    base_model,
                    param_grid=param_grid,
                    scoring=scorer,
                    cv=cv,
                    n_jobs=self.n_jobs
                )
            else:
                # No labels, use default anomaly score
                from sklearn.metrics import make_scorer
                
                # For unsupervised case, we'll use the negative of average anomaly score
                # as a simple metric (lower is better)
                def unsupervised_score(estimator, X_eval):
                    scores = 1 - (1 + estimator.decision_function(X_eval)) / 2
                    return -np.mean(scores)  # negative because GridSearchCV maximizes score
                
                scorer = make_scorer(unsupervised_score)
                
                # Create GridSearchCV with custom CV that uses same data for train/test
                class SameDataCV:
                    def __init__(self, n_splits=1):
                        self.n_splits = n_splits
                    
                    def split(self, X, y=None, groups=None):
                        for _ in range(self.n_splits):
                            yield np.arange(len(X)), np.arange(len(X))
                    
                    def get_n_splits(self, X=None, y=None, groups=None):
                        return self.n_splits
                
                # Create GridSearchCV
                grid_search = GridSearchCV(
                    base_model,
                    param_grid=param_grid,
                    scoring=scorer,
                    cv=SameDataCV(n_splits=1),
                    n_jobs=self.n_jobs
                )
            
            # Run grid search
            logger.info("Starting hyperparameter optimization...")
            grid_search.fit(X)
            logger.info(f"Best parameters: {grid_search.best_params_}")
            
            # Update model with best parameters
            self.n_estimators = grid_search.best_params_.get('n_estimators', self.n_estimators)
            self.max_samples = grid_search.best_params_.get('max_samples', self.max_samples)
            self.contamination = grid_search.best_params_.get('contamination', self.contamination)
            self.max_features = grid_search.best_params_.get('max_features', self.max_features)
            
            # Create new model with best parameters
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                max_samples=self.max_samples,
                contamination=self.contamination,
                max_features=self.max_features,
                bootstrap=self.bootstrap,
                n_jobs=self.n_jobs,
                random_state=self.random_state,
                verbose=0
            )
            
            # Return best parameters
            return grid_search.best_params_
            
        except ImportError:
            logger.warning("sklearn GridSearchCV not available. Skipping hyperparameter optimization.")
            return {}
    
    def _save_model_data(self, path: str) -> str:
        """
        Save model data to disk
        
        Args:
            path: Directory path
            
        Returns:
            Path to saved model file
        """
        model_path = os.path.join(path, "isolation_forest.pkl")
        with open(model_path, "wb") as f:
            pickle.dump(self.model, f)
            
        # Save feature importances
        if self.feature_importances_ is not None:
            importances_path = os.path.join(path, "feature_importances.json")
            with open(importances_path, "w") as f:
                json.dump({
                    "feature_importances": self.feature_importances_.tolist()
                }, f, indent=2)
                
        # Save scaler if used
        if self.auto_scale and self.scaler is not None:
            scaler_path = os.path.join(path, "scaler.pkl")
            with open(scaler_path, "wb") as f:
                pickle.dump(self.scaler, f)
                
        # Save selected features if feature selection was used
        if self.selected_features is not None:
            selected_features_path = os.path.join(path, "selected_features.json")
            with open(selected_features_path, "w") as f:
                json.dump({
                    "selected_features": self.selected_features.tolist(),
                    "feature_importance_threshold": self.feature_importance_threshold
                }, f, indent=2)
                
        return model_path
        
    @classmethod
    def load(cls, path: str) -> 'IsolationForestModel':
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
        
        # Load scikit-learn model
        model_path = os.path.join(path, "isolation_forest.pkl")
        with open(model_path, "rb") as f:
            model.model = pickle.load(f)
            
        # Load feature importances
        importances_path = os.path.join(path, "feature_importances.json")
        if os.path.exists(importances_path):
            with open(importances_path, "r") as f:
                importances_data = json.load(f)
                model.feature_importances_ = np.array(importances_data["feature_importances"])
        
        # Load scaler if it exists
        scaler_path = os.path.join(path, "scaler.pkl")
        if os.path.exists(scaler_path):
            with open(scaler_path, "rb") as f:
                model.scaler = pickle.load(f)
                model.auto_scale = True
                
        # Load selected features if they exist
        selected_features_path = os.path.join(path, "selected_features.json")
        if os.path.exists(selected_features_path):
            with open(selected_features_path, "r") as f:
                features_data = json.load(f)
                model.selected_features = np.array(features_data["selected_features"])
                model.feature_importance_threshold = features_data["feature_importance_threshold"]
                model.feature_selection = True
        
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
    
    def plot_anomaly_scores(self, scores: np.ndarray, title: str = "Anomaly Score Distribution") -> Any:
        """
        Plot the distribution of anomaly scores
        
        Args:
            scores: Anomaly scores
            title: Plot title
            
        Returns:
            Plot object
        """
        try:
            import matplotlib.pyplot as plt
            
            plt.figure(figsize=(10, 6))
            plt.hist(scores, bins=50, alpha=0.7)
            plt.axvline(x=self.threshold, color='r', linestyle='--', label=f'Threshold = {self.threshold:.3f}')
            plt.xlabel('Anomaly Score')
            plt.ylabel('Count')
            plt.title(title)
            plt.legend()
            plt.grid(True, alpha=0.3)
            
            return plt
        except ImportError:
            logger.warning("matplotlib not available. Cannot create plot.")
            return None


# Helper function to compare anomaly scores from different models
def compare_anomaly_scores(scores_dict: Dict[str, np.ndarray]) -> Any:
    """
    Compare anomaly scores from multiple models
    
    Args:
        scores_dict: Dictionary mapping model names to score arrays
        
    Returns:
        Plot object
    """
    try:
        import matplotlib.pyplot as plt
        
        plt.figure(figsize=(12, 8))
        
        for model_name, scores in scores_dict.items():
            plt.hist(scores, bins=50, alpha=0.5, label=model_name)
            
        plt.xlabel('Anomaly Score')
        plt.ylabel('Count')
        plt.title('Anomaly Score Comparison Across Models')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        return plt
    except ImportError:
        logger.warning("matplotlib not available. Cannot create comparison plot.")
        return None


# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 18:35:32"
__author__ = "Rahul"
