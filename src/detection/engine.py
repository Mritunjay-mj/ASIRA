"""
Core detection engine for ASIRA
Implements multi-model anomaly detection for security events

This module combines multiple detection techniques including:
1. Statistical methods (z-scores, MAD)
2. Machine learning (Isolation Forest)
3. Deep learning (autoencoder neural networks)

Version: 1.0.0
Last updated: 2025-03-15 17:56:45
Last updated by: Rahul
"""

import os
import numpy as np
import pandas as pd
import time
import logging
import pickle
import uuid
import json
import glob
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Union, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, precision_recall_curve, average_precision_score
import torch
import torch.nn as nn
import torch.nn.functional as F

from src.common.config import Settings

# Initialize logger
from src.common.logging_config import get_logger
logger = get_logger("asira.detection.engine")

# Initialize settings
settings = Settings()

@dataclass
class AnomalyDetectionResult:
    """Represents the result of anomaly detection for a single event."""
    event_id: str
    anomaly_score: float
    detection_method: str
    explanation: Dict[str, float]
    related_events: List[str]
    confidence: float
    timestamp: float = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)
    
    def to_json(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary"""
        result = self.to_dict()
        # Convert numpy types to Python native types for JSON serialization
        for key in ["anomaly_score", "confidence"]:
            if key in result and isinstance(result[key], (np.float32, np.float64)):
                result[key] = float(result[key])
                
        # Convert explanation values to float if they are numpy types
        if "explanation" in result:
            for k, v in result["explanation"].items():
                if isinstance(v, (np.float32, np.float64)):
                    result["explanation"][k] = float(v)
                
        return result


class Autoencoder(nn.Module):
    """
    Autoencoder neural network for anomaly detection
    
    Compresses input data to a lower-dimensional encoding and reconstructs it
    High reconstruction error indicates anomalous data
    """
    def __init__(self, input_dim: int, encoding_dim: int, hidden_layers: List[int] = None):
        """
        Initialize autoencoder with input and encoding dimensions
        
        Args:
            input_dim: Dimension of input features
            encoding_dim: Dimension of the encoding (compressed representation)
            hidden_layers: List of hidden layer dimensions for more complex architectures
        """
        super(Autoencoder, self).__init__()
        
        if hidden_layers is None:
            # Default architecture - single hidden layer
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, encoding_dim * 2),
                nn.ReLU(True),
                nn.BatchNorm1d(encoding_dim * 2),
                nn.Dropout(0.2),
                nn.Linear(encoding_dim * 2, encoding_dim),
                nn.ReLU(True)
            )
            
            self.decoder = nn.Sequential(
                nn.Linear(encoding_dim, encoding_dim * 2),
                nn.ReLU(True),
                nn.BatchNorm1d(encoding_dim * 2),
                nn.Dropout(0.2),
                nn.Linear(encoding_dim * 2, input_dim),
                nn.Sigmoid()
            )
        else:
            # Custom architecture with specified hidden layers
            # Build encoder
            encoder_layers = []
            prev_dim = input_dim
            for hidden_dim in hidden_layers:
                encoder_layers.append(nn.Linear(prev_dim, hidden_dim))
                encoder_layers.append(nn.ReLU(True))
                encoder_layers.append(nn.BatchNorm1d(hidden_dim))
                encoder_layers.append(nn.Dropout(0.2))
                prev_dim = hidden_dim
            
            # Final encoding layer
            encoder_layers.append(nn.Linear(prev_dim, encoding_dim))
            encoder_layers.append(nn.ReLU(True))
            
            self.encoder = nn.Sequential(*encoder_layers)
            
            # Build decoder (mirror of encoder)
            decoder_layers = []
            prev_dim = encoding_dim
            for hidden_dim in reversed(hidden_layers):
                decoder_layers.append(nn.Linear(prev_dim, hidden_dim))
                decoder_layers.append(nn.ReLU(True))
                decoder_layers.append(nn.BatchNorm1d(hidden_dim))
                decoder_layers.append(nn.Dropout(0.2))
                prev_dim = hidden_dim
                
            # Final reconstruction layer
            decoder_layers.append(nn.Linear(prev_dim, input_dim))
            decoder_layers.append(nn.Sigmoid())
            
            self.decoder = nn.Sequential(*decoder_layers)
        
    def forward(self, x):
        """Forward pass through the autoencoder"""
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        """Encode input data to the compressed representation"""
        return self.encoder(x)


class MultiModelDetector:
    """
    Implements multiple anomaly detection techniques and combines their results.
    Uses ensemble approach to improve accuracy and robustness.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the detector with configuration parameters
        
        Args:
            config: Configuration dictionary with detection parameters
        """
        self.config = config
        self._initialize_models()
        self.scaler = StandardScaler()
        self.feature_names = config.get("feature_names", [])
        self.threshold = config.get("threshold", 0.7)
        self.model_weights = config.get("model_weights", {
            "statistical": 1.0,
            "isolation_forest": 1.0,
            "autoencoder": 1.0
        })
        self.trained = False
        
        # Additional parameters for model management
        self.model_id = config.get("model_id", f"model_{uuid.uuid4().hex[:8]}")
        self.version = config.get("version", "1.0.0")
        self.created_at = time.time()
        self.updated_at = self.created_at
        self.training_stats = {}
        
        # Cache for recently detected anomalies to avoid duplicates
        self.recent_anomalies = set()
        self.max_cache_size = config.get("max_cache_size", 1000)
        
        logger.info(f"Initialized MultiModelDetector with threshold {self.threshold}")
    
    def _initialize_models(self):
        """Initialize detection models based on configuration."""
        self.models = {}
        
        # Statistical model
        if self.config.get("use_statistical", True):
            logger.info("Initializing statistical detection model")
            self.models["statistical"] = self._create_statistical_model()
        
        # Machine learning model
        if self.config.get("use_isolation_forest", True):
            logger.info("Initializing isolation forest model")
            self.models["isolation_forest"] = self._create_isolation_forest()
        
        # Deep learning model
        if self.config.get("use_autoencoder", True):
            logger.info("Initializing autoencoder model")
            self.models["autoencoder"] = self._create_autoencoder()
    
    def _create_statistical_model(self):
        """Create a statistical anomaly detection model."""
        return {
            "z_score_threshold": self.config.get("z_score_threshold", 3.0),
            "mad_threshold": self.config.get("mad_threshold", 3.0),
            "mean": None,
            "std": None,
            "median": None,
            "mad": None  # Median Absolute Deviation for robust statistics
        }
    
    def _create_isolation_forest(self):
        """Create an Isolation Forest model for anomaly detection."""
        return IsolationForest(
            n_estimators=self.config.get("n_estimators", 100),
            max_samples=self.config.get("max_samples", "auto"),
            contamination=self.config.get("contamination", 0.01),
            max_features=self.config.get("max_features", 1.0),
            bootstrap=self.config.get("bootstrap", False),
            random_state=42,
            n_jobs=self.config.get("n_jobs", -1),
            verbose=0
        )
    
    def _create_autoencoder(self):
        """Create an autoencoder neural network for anomaly detection."""
        input_dim = self.config.get("input_dim", 20)
        encoding_dim = self.config.get("encoding_dim", 10)
        hidden_layers = self.config.get("hidden_layers", None)
        
        return Autoencoder(input_dim, encoding_dim, hidden_layers)
    
    def train(self, normal_data: pd.DataFrame, validation_data: Optional[pd.DataFrame] = None):
        """
        Train the detector models on normal data.
        
        Args:
            normal_data: DataFrame containing normal behavior patterns
            validation_data: Optional DataFrame containing labeled data for validation
        
        Raises:
            ValueError: If normal_data is empty
        """
        if len(normal_data) == 0:
            raise ValueError("Cannot train on empty dataset")
        
        logger.info(f"Training detection models on {len(normal_data)} normal events")
        
        training_start = time.time()
        
        # Prepare data
        X = normal_data.values
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        # Train Isolation Forest
        if "isolation_forest" in self.models:
            logger.info("Training isolation forest model")
            start_time = time.time()
            self.models["isolation_forest"].fit(X_scaled)
            self.training_stats["isolation_forest"] = {
                "training_time": time.time() - start_time,
            }
            
        # Train Autoencoder
        if "autoencoder" in self.models:
            logger.info("Training autoencoder model")
            start_time = time.time()
            autoencoder = self.models["autoencoder"]
            
            # Convert to PyTorch tensor
            X_tensor = torch.FloatTensor(X_scaled)
            
            # Training parameters
            criterion = nn.MSELoss()
            optimizer = torch.optim.Adam(
                autoencoder.parameters(),
                lr=self.config.get("learning_rate", 0.001),
                weight_decay=self.config.get("weight_decay", 1e-5)
            )
            epochs = self.config.get("epochs", 50)
            batch_size = self.config.get("batch_size", 32)
            early_stopping_patience = self.config.get("early_stopping_patience", 10)
            
            # For early stopping
            best_loss = float('inf')
            patience_counter = 0
            
            # Track training history
            history = {
                "train_loss": [],
                "val_loss": []
            }
            
            # Training loop
            for epoch in range(epochs):
                # Training mode
                autoencoder.train()
                
                permutation = torch.randperm(X_tensor.size()[0])
                total_loss = 0
                
                for i in range(0, X_tensor.size()[0], batch_size):
                    indices = permutation[i:i + batch_size]
                    batch_x = X_tensor[indices]
                    
                    # Forward pass
                    outputs = autoencoder(batch_x)
                    loss = criterion(outputs, batch_x)
                    
                    # Backward and optimize
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                    
                    total_loss += loss.item() * batch_x.size(0)
                
                avg_loss = total_loss / X_tensor.size(0)
                history["train_loss"].append(avg_loss)
                
                # Validation if provided
                if validation_data is not None and len(validation_data) > 0:
                    autoencoder.eval()  # Evaluation mode
                    X_val = validation_data.values
                    X_val_scaled = self.scaler.transform(X_val)
                    X_val_tensor = torch.FloatTensor(X_val_scaled)
                    
                    with torch.no_grad():
                        val_outputs = autoencoder(X_val_tensor)
                        val_loss = criterion(val_outputs, X_val_tensor)
                    
                    history["val_loss"].append(val_loss.item())
                    
                    if val_loss < best_loss:
                        best_loss = val_loss
                        patience_counter = 0
                    else:
                        patience_counter += 1
                        
                    # Early stopping
                    if patience_counter >= early_stopping_patience:
                        logger.info(f"Early stopping at epoch {epoch}")
                        break
                        
                    log_message = f'Epoch [{epoch+1}/{epochs}], Train Loss: {avg_loss:.4f}, Val Loss: {val_loss:.4f}'
                else:
                    # Without validation data, use training loss for early stopping
                    if avg_loss < best_loss:
                        best_loss = avg_loss
                        patience_counter = 0
                    else:
                        patience_counter += 1
                        
                    # Early stopping
                    if patience_counter >= early_stopping_patience:
                        logger.info(f"Early stopping at epoch {epoch+1}")
                        break
                        
                    log_message = f'Epoch [{epoch+1}/{epochs}], Loss: {avg_loss:.4f}'
                
                # Log every 5 epochs
                if (epoch + 1) % 5 == 0:
                    logger.info(log_message)
            
            # Save training stats
            self.training_stats["autoencoder"] = {
                "training_time": time.time() - start_time,
                "epochs": epoch + 1,
                "final_loss": avg_loss,
                "best_loss": best_loss,
                "history": history
            }
        
        # For statistical model, calculate baseline statistics
        if "statistical" in self.models:
            logger.info("Training statistical model")
            start_time = time.time()
            
            # Standard stats
            self.models["statistical"]["mean"] = np.mean(X, axis=0)
            self.models["statistical"]["std"] = np.std(X, axis=0)
            
            # Robust stats (median and MAD)
            self.models["statistical"]["median"] = np.median(X, axis=0)
            self.models["statistical"]["mad"] = np.median(np.abs(X - self.models["statistical"]["median"]), axis=0) * 1.4826
            
            self.training_stats["statistical"] = {
                "training_time": time.time() - start_time,
            }
            
        # Update training metadata
        self.trained = True
        self.updated_at = time.time()
        
        # Record overall training stats
        self.training_stats["total_training_time"] = time.time() - training_start
        self.training_stats["num_samples"] = len(normal_data)
        self.training_stats["num_features"] = X.shape[1]
        self.training_stats["feature_names"] = self.feature_names
        
        logger.info(f"Model training completed in {self.training_stats['total_training_time']:.2f} seconds")
    
    def detect(self, event_data: pd.DataFrame) -> List[AnomalyDetectionResult]:
        """
        Detect anomalies in the provided event data.
        
        Args:
            event_data: DataFrame containing events to analyze
            
        Returns:
            List of AnomalyDetectionResult for anomalous events
        """
        if len(event_data) == 0:
            return []
            
        if not self.trained:
            logger.warning("Models not trained, detection may not be accurate")
            
        logger.info(f"Analyzing {len(event_data)} events for anomalies")
        
        results = []
        
        # Prepare data
        X = event_data.values
        event_ids = event_data.index.tolist()
        
        # Store raw data for reference
        raw_data = {}
        for i, event_id in enumerate(event_ids):
            raw_data[event_id] = {
                column: event_data.iloc[i][column]
                for column in event_data.columns
            }
        
        # Scale data
        X_scaled = self.scaler.transform(X)
        
        # Get scores from each model
        scores = {}
        explanations = {}
        
        # Statistical detection
        if "statistical" in self.models:
            logger.debug("Running statistical anomaly detection")
            stat_model = self.models["statistical"]
            
            # Skip if not trained
            if stat_model["mean"] is None or stat_model["std"] is None:
                logger.warning("Statistical model not trained, skipping")
            else:
                # Z-score based detection (good for normal distributions)
                mean = stat_model["mean"]
                std = stat_model["std"]
                
                # Avoid division by zero
                std = np.where(std < 1e-10, 1e-10, std)
                
                z_scores = np.abs((X - mean) / std)
                stat_scores_zscore = np.mean(z_scores, axis=1)
                
                # MAD-based detection (more robust to outliers)
                median = stat_model["median"] 
                mad = stat_model["mad"]
                
                # Avoid division by zero
                mad = np.where(mad < 1e-10, 1e-10, mad)
                
                mad_scores = np.abs((X - median) / mad)
                stat_scores_mad = np.mean(mad_scores, axis=1)
                
                # Combine both scores (average)
                stat_scores = (stat_scores_zscore + stat_scores_mad) / 2
                
                # Normalize to 0-1 range
                max_score = np.max(stat_scores)
                if max_score > 0:
                    stat_scores = stat_scores / max_score
                    
                scores["statistical"] = stat_scores
                
                # Generate explanations based on feature contributions
                for i, event_id in enumerate(event_ids):
                    # Calculate feature importance based on both z-score and mad
                    feature_importance = {}
                    for j in range(X.shape[1]):
                        # Combine both measures
                        feature_name = self.feature_names[j] if j < len(self.feature_names) else f"feature_{j}"
                        z_importance = z_scores[i, j] / np.sum(z_scores[i])
                        mad_importance = mad_scores[i, j] / np.sum(mad_scores[i])
                        # Average both
                        feature_importance[feature_name] = (z_importance + mad_importance) / 2
                        
                    if event_id not in explanations:
                        explanations[event_id] = {}
                        
                    explanations[event_id]["statistical"] = feature_importance
        
        # Isolation Forest detection
        if "isolation_forest" in self.models:
            logger.debug("Running Isolation Forest anomaly detection")
            # Convert -1/1 to anomaly scores where higher is more anomalous
            raw_scores = self.models["isolation_forest"].decision_function(X_scaled)
            iso_scores = 1.0 - (1.0 + raw_scores) / 2.0
            scores["isolation_forest"] = iso_scores
            
            # Generate feature importance using permutation importance
            # In a real implementation, this would use SHAP values or permutation importance
            # For this prototype, we'll use a simplified approach
            for i, event_id in enumerate(event_ids):
                if event_id not in explanations:
                    explanations[event_id] = {}
                
                # Create random feature importance as placeholder
                # In production, use SHAP or permutation importance
                feature_importance = {}
                for j in range(X.shape[1]):
                    feature_name = self.feature_names[j] if j < len(self.feature_names) else f"feature_{j}"
                    # Create synthetic feature importance based on feature value's deviation
                    importance = abs(X_scaled[i, j]) / np.sum(abs(X_scaled[i]))
                    feature_importance[feature_name] = importance
                    
                explanations[event_id]["isolation_forest"] = feature_importance
        
        # Autoencoder detection
        if "autoencoder" in self.models:
            logger.debug("Running Autoencoder anomaly detection")
            autoencoder = self.models["autoencoder"]
            X_tensor = torch.FloatTensor(X_scaled)
            
            # Set model to evaluation mode
            autoencoder.eval()
            
            # Get reconstructions
            with torch.no_grad():
                reconstructions = autoencoder(X_tensor).numpy()
            
            # Calculate reconstruction error (MSE)
            mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
            
            # Normalize to 0-1 range
            max_mse = np.max(mse)
            if max_mse > 0:
                autoencoder_scores = mse / max_mse
            else:
                autoencoder_scores = mse
                
            scores["autoencoder"] = autoencoder_scores
            
            # Generate explanations based on reconstruction error
            for i, event_id in enumerate(event_ids):
                if event_id not in explanations:
                    explanations[event_id] = {}
                
                # Calculate feature importance based on reconstruction error
                feature_importance = {}
                feature_errors = np.power(X_scaled[i] - reconstructions[i], 2)
                sum_errors = np.sum(feature_errors)
                
                if sum_errors > 0:
                    for j in range(X.shape[1]):
                        feature_name = self.feature_names[j] if j < len(self.feature_names) else f"feature_{j}"
                        importance = feature_errors[j] / sum_errors
                        feature_importance[feature_name] = float(importance)
                else:
                    # If no reconstruction error, assign equal importance
                    for j in range(X.shape[1]):
                        feature_name = self.feature_names[j] if j < len(self.feature_names) else f"feature_{j}"
                        feature_importance[feature_name] = 1.0 / X.shape[1]
                
                explanations[event_id]["autoencoder"] = feature_importance
        
        # Combine scores and generate results
        for i, event_id in enumerate(event_ids):
            # Calculate weighted average score across models
            model_scores = {}
            for model in scores:
                model_scores[model] = scores[model][i] * self.model_weights.get(model, 1.0)
            
            if not model_scores:
                continue
                
            # Weighted average
            weight_sum = sum(self.model_weights.get(model, 1.0) for model in model_scores)
            if weight_sum > 0:
                combined_score = sum(model_scores.values()) / weight_sum
            else:
                combined_score = sum(model_scores.values()) / len(model_scores)
            
            # Only report if above threshold and not in recent cache
            if combined_score > self.threshold and event_id not in self.recent_anomalies:
                # Determine which model had highest confidence
                best_model = max(model_scores.items(), key=lambda x: x[1])[0]
                
                # Get explanation for this model
                model_explanation = explanations.get(event_id, {}).get(best_model, {})
                
                # Create result
                result = AnomalyDetectionResult(
                    event_id=event_id,
                    anomaly_score=float(combined_score),
                    detection_method=best_model,
                    explanation=model_explanation,
                    related_events=self._find_related_events(event_id, event_data),
                    confidence=float(model_scores[best_model] / self.model_weights.get(best_model, 1.0)),
                    raw_data=raw_data.get(event_id, {})
                )
                results.append(result)
                
                # Add to recent anomalies cache
                self.recent_anomalies.add(event_id)
                
                # Manage cache size
                if len(self.recent_anomalies) > self.max_cache_size:
                    self.recent_anomalies.pop()
        
        logger.info(f"Detection completed. Found {len(results)} anomalies")
        return results
    
    def detect_real_time(self, event: Dict[str, Any]) -> Optional[AnomalyDetectionResult]:
        """
        Perform real-time anomaly detection on a single event
        
        Args:
            event: Dictionary containing event data
            
        Returns:
            AnomalyDetectionResult if anomaly detected, None otherwise
        """
        if not self.trained:
            logger.warning("Models not trained, detection may not be accurate")
        
        # Convert to DataFrame for consistency with batch processing
        event_df = pd.DataFrame([event])
        
        # Add an index for the event
        event_id = event.get("id", str(uuid.uuid4()))
        event_df.index = [event_id]
        
        # Check if we've seen this event before
        if event_id in self.recent_anomalies:
            return None
        
        # Run detection
        results = self.detect(event_df)
        
        # Return first result if any, otherwise None
        return results[0] if results else None
    
    def _find_related_events(self, event_id: str, event_data: pd.DataFrame) -> List[str]:
        """
        Find events that might be related to the detected anomaly.
        
        Args:
            event_id: ID of the anomalous event
            event_data: DataFrame containing all events
            
        Returns:
            List of related event IDs
        """
        # Get the index of the current event
        try:
            current_idx = event_data.index.get_loc(event_id)
        except (KeyError, TypeError):
            return []
            
        # Get timestamp column if available
        timestamp_col = None
        for col in ['timestamp', 'time', 'date', 'datetime']:
            if col in event_data.columns:
                timestamp_col = col
                break
        
        related = []
        
        # If we have timestamps, find events close in time
        if timestamp_col:
            try:
                current_time = event_data.iloc[current_idx][timestamp_col]
                # Define time window (e.g., events within 5 minutes)
                time_window = 300  # 5 minutes in seconds
                
                # Find events within the time window
                for idx, row in event_data.iterrows():
                    if idx != event_id:  # Skip the current event
                        event_time = row[timestamp_col]
                        if abs(event_time - current_time) <= time_window:
                            related.append(idx)
            except (KeyError, TypeError, IndexError):
                pass
        
        # If no related events found by time, get events before and after
        if not related:
            # Get a few events before and after
            start_idx = max(0, current_idx - 2)
            end_idx = min(len(event_data), current_idx + 3)
            
            # Add surrounding events
            for idx in range(start_idx, end_idx):
                if idx != current_idx:  # Skip the current event
                    related.append(event_data.index[idx])
        
        # Limit the number of related events
        max_related = 5
        if len(related) > max_related:
            related = related[:max_related]
            
        return related
    
    def evaluate(self, test_data: pd.DataFrame, labels: List[bool]) -> Dict[str, float]:
        """
        Evaluate detector performance using labeled test data
        
        Args:
            test_data: DataFrame containing test events
            labels: List of boolean labels (True for anomalies, False for normal)
            
        Returns:
            Dictionary with evaluation metrics
        """
        if len(test_data) == 0 or len(labels) != len(test_data):
            raise ValueError("Test data empty or labels don't match data length")
        
        # Get anomaly scores
        X = test_data.values
        X_scaled = self.scaler.transform(X)
        
        # Store scores from each model
        model_scores = {}
        
        # Statistical detection
        if "statistical" in self.models:
            stat_model = self.models["statistical"]
            if stat_model["mean"] is not None and stat_model["std"] is not None:
                mean = stat_model["mean"]
                std = stat_model["std"]
                std = np.where(std < 1e-10, 1e-10, std)
                z_scores = np.abs((X - mean) / std)
                model_scores["statistical"] = np.mean(z_scores, axis=1)
        
        # Isolation Forest
        if "isolation_forest" in self.models:
            raw_scores = self.models["isolation_forest"].decision_function(X_scaled)
            model_scores["isolation_forest"] = 1.0 - (1.0 + raw_scores) / 2.0
        
        # Autoencoder
        if "autoencoder" in self.models:
            autoencoder = self.models["autoencoder"]
            X_tensor = torch.FloatTensor(X_scaled)
            
            with torch.no_grad():
                reconstructions = autoencoder(X_tensor).numpy()
                
            mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
            model_scores["autoencoder"] = mse / np.max(mse) if np.max(mse) > 0 else mse
        
        # Calculate combined scores using model weights
        if model_scores:
            combined_scores = np.zeros(len(test_data))
            weight_sum = 0
            
            for model, scores in model_scores.items():
                weight = self.model_weights.get(model, 1.0)
                combined_scores += scores * weight
                weight_sum += weight
                
            if weight_sum > 0:
                combined_scores /= weight_sum
                
            # Calculate evaluation metrics
            try:
                # AUC ROC
                auc_roc = roc_auc_score(labels, combined_scores)
                
                # Precision, recall, F1 at optimal threshold
                precision, recall, thresholds = precision_recall_curve(labels, combined_scores)
                f1_scores = 2 * precision * recall / (precision + recall + 1e-10)
                optimal_idx = np.argmax(f1_scores)
                optimal_threshold = thresholds[optimal_idx] if optimal_idx < len(thresholds) else 0.5
                
                # Average precision
                ap = average_precision_score(labels, combined_scores)
                
                # Get predictions at optimal threshold
                predictions = combined_scores >= optimal_threshold
                
                # Calculate metrics
                true_positives = np.sum(np.logical_and(predictions, labels))
                false_positives = np.sum(np.logical_and(predictions, np.logical_not(labels)))
                true_negatives = np.sum(np.logical_and(np.logical_not(predictions), np.logical_not(labels)))
                false_negatives = np.sum(np.logical_and(np.logical_not(predictions), labels))
                
                precision_at_threshold = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
                recall_at_threshold = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
                f1_at_threshold = 2 * precision_at_threshold * recall_at_threshold / (precision_at_threshold + recall_at_threshold) if (precision_at_threshold + recall_at_threshold) > 0 else 0
                
                return {
                    "auc_roc": float(auc_roc),
                    "average_precision": float(ap),
                    "optimal_threshold": float(optimal_threshold),
                    "precision": float(precision_at_threshold),
                    "recall": float(recall_at_threshold),
                    "f1_score": float(f1_at_threshold),
                    "true_positives": int(true_positives),
                    "false_positives": int(false_positives),
                    "true_negatives": int(true_negatives),
                    "false_negatives": int(false_negatives)
                }
            except Exception as e:
                logger.error(f"Error calculating evaluation metrics: {e}")
                return {"error": str(e)}
        
        return {"error": "No models available for evaluation"}
    
    def save_models(self, path: str):
        """
        Save trained models to disk
        
        Args:
            path: Directory path to save models
        """
        if not self.trained:
            logger.warning("Models not trained, saving may result in untrained models")
            
        os.makedirs(path, exist_ok=True)
        
        # Save configuration and metadata
        config_path = os.path.join(path, "config.json")
        with open(config_path, "w") as f:
            config_data = {
                "model_id": self.model_id,
                "version": self.version,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "threshold": self.threshold,
                "feature_names": self.feature_names,
                "model_weights": self.model_weights,
                "training_stats": self.training_stats
            }
            json.dump(config_data, f, indent=2)
            
        # Save standard scaler
        scaler_path = os.path.join(path, "scaler.pkl")
        with open(scaler_path, "wb") as f:
            pickle.dump(self.scaler, f)
            
        # Save individual models
        for model_name, model in self.models.items():
            if model_name == "statistical":
                # Statistical model is a dictionary, save as JSON
                stat_path = os.path.join(path, "statistical.json")
                with open(stat_path, "w") as f:
                    # Convert numpy arrays to lists for JSON serialization
                    stat_data = {
                        "z_score_threshold": model["z_score_threshold"],
                        "mad_threshold": model["mad_threshold"],
                        "mean": model["mean"].tolist() if model["mean"] is not None else None,
                        "std": model["std"].tolist() if model["std"] is not None else None,
                        "median": model["median"].tolist() if model["median"] is not None else None,
                        "mad": model["mad"].tolist() if model["mad"] is not None else None
                    }
                    json.dump(stat_data, f, indent=2)
            elif model_name == "isolation_forest":
                # Isolation Forest is a sklearn model, save with pickle
                iso_path = os.path.join(path, "isolation_forest.pkl")
                with open(iso_path, "wb") as f:
                    pickle.dump(model, f)
            elif model_name == "autoencoder":
                # Autoencoder is a PyTorch model, save state dict
                ae_path = os.path.join(path, "autoencoder.pt")
                torch.save(model.state_dict(), ae_path)
                
                # Also save architecture info
                ae_config_path = os.path.join(path, "autoencoder_config.json")
                with open(ae_config_path, "w") as f:
                    json.dump({
                        "input_dim": next(model.encoder.parameters()).size(1),
                        "encoding_dim": next(model.decoder.parameters()).size(1),
                        "hidden_layers": self.config.get("hidden_layers")
                    }, f, indent=2)
        
        logger.info(f"Models saved to {path}")
    
    def load_models(self, path: str):
        """
        Load trained models from disk
        
        Args:
            path: Directory path to load models from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Load configuration and metadata
            config_path = os.path.join(path, "config.json")
            with open(config_path, "r") as f:
                config_data = json.load(f)
                
            self.model_id = config_data["model_id"]
            self.version = config_data["version"]
            self.created_at = config_data["created_at"]
            self.updated_at = config_data["updated_at"]
            self.threshold = config_data["threshold"]
            self.feature_names = config_data["feature_names"]
            self.model_weights = config_data["model_weights"]
            self.training_stats = config_data["training_stats"]
            
            # Load standard scaler
            scaler_path = os.path.join(path, "scaler.pkl")
            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)
                
            # Load individual models
            # Statistical model
            stat_path = os.path.join(path, "statistical.json")
            if os.path.exists(stat_path):
                with open(stat_path, "r") as f:
                    stat_data = json.load(f)
                    
                # Initialize statistical model
                self.models["statistical"] = {
                    "z_score_threshold": stat_data["z_score_threshold"],
                    "mad_threshold": stat_data["mad_threshold"],
                    "mean": np.array(stat_data["mean"]) if stat_data["mean"] is not None else None,
                    "std": np.array(stat_data["std"]) if stat_data["std"] is not None else None,
                    "median": np.array(stat_data["median"]) if stat_data["median"] is not None else None,
                    "mad": np.array(stat_data["mad"]) if stat_data["mad"] is not None else None
                }
                
            # Isolation Forest
            iso_path = os.path.join(path, "isolation_forest.pkl")
            if os.path.exists(iso_path):
                with open(iso_path, "rb") as f:
                    self.models["isolation_forest"] = pickle.load(f)
                    
            # Autoencoder
            ae_path = os.path.join(path, "autoencoder.pt")
            ae_config_path = os.path.join(path, "autoencoder_config.json")
            if os.path.exists(ae_path) and os.path.exists(ae_config_path):
                with open(ae_config_path, "r") as f:
                    ae_config = json.load(f)
                    
                # Create autoencoder with same architecture
                autoencoder = Autoencoder(
                    input_dim=ae_config["input_dim"],
                    encoding_dim=ae_config["encoding_dim"],
                    hidden_layers=ae_config["hidden_layers"]
                )
                
                # Load weights
                autoencoder.load_state_dict(torch.load(ae_path))
                
                # Set to eval mode
                autoencoder.eval()
                
                self.models["autoencoder"] = autoencoder
                
            self.trained = True
            logger.info(f"Models loaded from {path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading models from {path}: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the trained models
        
        Returns:
            Dictionary with model metadata and statistics
        """
        model_info = {
            "model_id": self.model_id,
            "version": self.version,
            "created_at": datetime.fromtimestamp(self.created_at).isoformat(),
            "updated_at": datetime.fromtimestamp(self.updated_at).isoformat(),
            "trained": self.trained,
            "threshold": self.threshold,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "models": list(self.models.keys()),
            "model_weights": self.model_weights
        }
        
        # Add training stats if available
        if self.training_stats:
            model_info["training_stats"] = self.training_stats
            
        return model_info


class DetectionEngine:
    """
    Main detection engine that manages multiple detector models and 
    coordinates the detection workflow
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the detection engine
        
        Args:
            config: Engine configuration dictionary
        """
        self.config = config
        self.detector_configs = config.get("detectors", [])
        self.detectors = {}
        self.models_dir = config.get("models_dir", "models")
        self.active_detector = None
        
        # Initialize all configured detectors
        for detector_config in self.detector_configs:
            detector_id = detector_config.get("id", f"detector_{uuid.uuid4().hex[:8]}")
            self.detectors[detector_id] = MultiModelDetector(detector_config)
            
        # Set active detector (use first one by default)
        if self.detectors:
            self.active_detector = list(self.detectors.keys())[0]
            
        logger.info(f"Detection engine initialized with {len(self.detectors)} detectors")
        
    def train(self, detector_id: str, training_data: pd.DataFrame, validation_data: Optional[pd.DataFrame] = None) -> bool:
        """
        Train a specific detector
        
        Args:
            detector_id: ID of detector to train
            training_data: DataFrame with normal events for training
            validation_data: Optional validation data
            
        Returns:
            True if successful, False otherwise
        """
        if detector_id not in self.detectors:
            logger.error(f"Unknown detector ID: {detector_id}")
            return False
            
        try:
            detector = self.detectors[detector_id]
            detector.train(training_data, validation_data)
            
            # Save trained model
            model_path = os.path.join(self.models_dir, detector_id)
            detector.save_models(model_path)
            
            logger.info(f"Detector {detector_id} trained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error training detector {detector_id}: {e}")
            return False
            
    def detect(self, events: pd.DataFrame) -> List[AnomalyDetectionResult]:
        """
        Detect anomalies using the active detector
        
        Args:
            events: DataFrame containing events to analyze
            
        Returns:
            List of detection results
        """
        if not self.active_detector:
            logger.error("No active detector selected")
            return []
            
        if self.active_detector not in self.detectors:
            logger.error(f"Unknown active detector: {self.active_detector}")
            return []
            
        try:
            detector = self.detectors[self.active_detector]
            return detector.detect(events)
            
        except Exception as e:
            logger.error(f"Error during detection: {e}")
            return []
            
    def detect_real_time(self, event: Dict[str, Any]) -> Optional[AnomalyDetectionResult]:
        """
        Perform real-time detection on a single event
        
        Args:
            event: Dictionary containing event data
            
        Returns:
            Detection result if anomalous, None otherwise
        """
        if not self.active_detector:
            logger.error("No active detector selected")
            return None
            
        if self.active_detector not in self.detectors:
            logger.error(f"Unknown active detector: {self.active_detector}")
            return None
            
        try:
            detector = self.detectors[self.active_detector]
            return detector.detect_real_time(event)
            
        except Exception as e:
            logger.error(f"Error during real-time detection: {e}")
            return None
    
    def set_active_detector(self, detector_id: str) -> bool:
        """
        Set the active detector
        
        Args:
            detector_id: ID of detector to activate
            
        Returns:
            True if successful, False otherwise
        """
        if detector_id not in self.detectors:
            logger.error(f"Unknown detector ID: {detector_id}")
            return False
            
        self.active_detector = detector_id
        logger.info(f"Active detector set to {detector_id}")
        return True
        
    def load_detector(self, detector_id: str) -> bool:
        """
        Load a previously trained detector from disk
        
        Args:
            detector_id: ID of detector to load
            
        Returns:
            True if successful, False otherwise
        """
        model_path = os.path.join(self.models_dir, detector_id)
        
        if not os.path.exists(model_path):
            logger.error(f"Model directory not found: {model_path}")
            return False
            
        # Create new detector if it doesn't exist
        if detector_id not in self.detectors:
            self.detectors[detector_id] = MultiModelDetector({"id": detector_id})
            
        # Load the models
        result = self.detectors[detector_id].load_models(model_path)
        
        if result:
            logger.info(f"Detector {detector_id} loaded successfully")
            
            # Set as active if no active detector
            if not self.active_detector:
                self.active_detector = detector_id
                logger.info(f"Set {detector_id} as active detector")
                
        return result
        
    def list_detectors(self) -> Dict[str, Dict[str, Any]]:
        """
        List all available detectors with their status
        
        Returns:
            Dictionary mapping detector IDs to their status
        """
        result = {}
        
        # Add in-memory detectors
        for detector_id, detector in self.detectors.items():
            result[detector_id] = {
                "id": detector_id,
                "trained": detector.trained,
                "active": detector_id == self.active_detector,
                "in_memory": True,
                "info": detector.get_model_info() if detector.trained else {}
            }
            
        # Look for other saved models on disk
        if os.path.exists(self.models_dir):
            for entry in os.scandir(self.models_dir):
                if entry.is_dir() and entry.name not in result:
                    # Check if this is a valid model directory
                    config_path = os.path.join(entry.path, "config.json")
                    if os.path.exists(config_path):
                        try:
                            with open(config_path, "r") as f:
                                config_data = json.load(f)
                                
                            result[entry.name] = {
                                "id": entry.name,
                                "trained": True,
                                "active": False,
                                "in_memory": False,
                                "info": {
                                    "model_id": config_data.get("model_id", "unknown"),
                                    "version": config_data.get("version", "unknown"),
                                    "created_at": config_data.get("created_at", "unknown"),
                                    "updated_at": config_data.get("updated_at", "unknown")
                                }
                            }
                        except Exception:
                            pass
                            
        return result
        
    def evaluate_detector(self, detector_id: str, test_data: pd.DataFrame, labels: List[bool]) -> Dict[str, float]:
        """
        Evaluate a detector's performance
        
        Args:
            detector_id: ID of detector to evaluate
            test_data: Test data
            labels: True/False labels (True for anomalies)
            
        Returns:
            Evaluation metrics
        """
        if detector_id not in self.detectors:
            return {"error": f"Unknown detector ID: {detector_id}"}
            
        try:
            detector = self.detectors[detector_id]
            return detector.evaluate(test_data, labels)
            
        except Exception as e:
            logger.error(f"Error evaluating detector {detector_id}: {e}")
            return {"error": str(e)}
            
    def delete_detector(self, detector_id: str) -> bool:
        """
        Delete a detector and its saved models
        
        Args:
            detector_id: ID of detector to delete
            
        Returns:
            True if successful, False otherwise
        """
        # Remove from memory
        if detector_id in self.detectors:
            del self.detectors[detector_id]
            
        # If this was the active detector, reset active
        if self.active_detector == detector_id:
            self.active_detector = next(iter(self.detectors)) if self.detectors else None
            
        # Remove from disk
        model_path = os.path.join(self.models_dir, detector_id)
        if os.path.exists(model_path):
            try:
                import shutil
                shutil.rmtree(model_path)
                logger.info(f"Deleted detector {detector_id}")
                return True
            except Exception as e:
                logger.error(f"Error deleting detector {detector_id} from disk: {e}")
                return False
        
        return True


# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 17:59:36"
__author__ = "Rahul"
