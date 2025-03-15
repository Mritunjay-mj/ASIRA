"""
Autoencoder-based anomaly detection model

Uses neural network autoencoder for anomaly detection
based on reconstruction error

Version: 1.0.0
Last updated: 2025-03-15 18:39:04
Last updated by: Rahul
"""

import numpy as np
import pandas as pd
import pickle
import os
import json
import time
import warnings
from typing import Dict, Any, List, Tuple, Optional, Union, Sequence
from pathlib import Path

# PyTorch imports
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

from src.detection.models.base import BaseModel, ModelConfig
from src.common.logging_config import get_logger

# Initialize logger
logger = get_logger("asira.detection.models.autoencoder")

class Autoencoder(nn.Module):
    """
    Autoencoder neural network implementation
    """
    
    def __init__(self, input_dim: int, encoding_dim: int, hidden_layers: Optional[List[int]] = None):
        """
        Initialize autoencoder with configurable architecture
        
        Args:
            input_dim: Dimension of input features
            encoding_dim: Dimension of the encoding (compressed representation)
            hidden_layers: Optional list of hidden layer dimensions
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
        """
        Forward pass through the autoencoder
        
        Args:
            x: Input tensor
            
        Returns:
            Reconstructed output tensor
        """
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        """
        Encode the input to the latent space
        
        Args:
            x: Input tensor
            
        Returns:
            Encoded tensor
        """
        return self.encoder(x)
    
    def decode(self, x):
        """
        Decode from latent space
        
        Args:
            x: Encoded tensor
            
        Returns:
            Reconstructed output tensor
        """
        return self.decoder(x)


class AutoencoderModel(BaseModel):
    """
    Autoencoder-based anomaly detection model
    
    Uses reconstruction error to identify anomalies
    """
    
    def __init__(self, config: Union[Dict[str, Any], ModelConfig]):
        """
        Initialize autoencoder model
        
        Args:
            config: Model configuration
        """
        if isinstance(config, dict):
            config["model_type"] = "autoencoder"
            
        super().__init__(config)
        
        # Extract autoencoder parameters
        self.input_dim = self.config.config.get("input_dim", 20)
        self.encoding_dim = self.config.config.get("encoding_dim", 10)
        self.hidden_layers = self.config.config.get("hidden_layers", None)
        
        # Training parameters
        self.learning_rate = self.config.config.get("learning_rate", 0.001)
        self.weight_decay = self.config.config.get("weight_decay", 1e-5)
        self.batch_size = self.config.config.get("batch_size", 32)
        self.epochs = self.config.config.get("epochs", 50)
        self.early_stopping = self.config.config.get("early_stopping", True)
        self.patience = self.config.config.get("patience", 10)
        self.validation_split = self.config.config.get("validation_split", 0.1)
        
        # Device configuration
        self.device = self._get_device()
        
        # Create the autoencoder
        self.model = Autoencoder(
            input_dim=self.input_dim,
            encoding_dim=self.encoding_dim,
            hidden_layers=self.hidden_layers
        ).to(self.device)
        
        # Initialize optimizer
        self.optimizer = None
        
        # For normalization of input data
        self.scaler_mean = None
        self.scaler_std = None
        
        # For anomaly thresholding
        self.reconstruction_errors = None
        
    def _get_device(self) -> torch.device:
        """Get the appropriate device (CPU or GPU)"""
        if torch.cuda.is_available():
            return torch.device("cuda")
        else:
            return torch.device("cpu")
    
    def _normalize_data(self, X: np.ndarray) -> np.ndarray:
        """
        Normalize input data
        
        Args:
            X: Input data
            
        Returns:
            Normalized data
        """
        # Apply preprocessing from base class
        X = self.preprocess(X)
        
        if self.scaler_mean is None or self.scaler_std is None:
            # First time, compute mean and std
            self.scaler_mean = np.mean(X, axis=0)
            self.scaler_std = np.std(X, axis=0)
            # Handle zero std
            self.scaler_std[self.scaler_std < 1e-10] = 1.0
        
        # Normalize
        X_norm = (X - self.scaler_mean) / self.scaler_std
        
        return X_norm
    
    def _denormalize_data(self, X_norm: np.ndarray) -> np.ndarray:
        """
        Denormalize data back to original scale
        
        Args:
            X_norm: Normalized data
            
        Returns:
            Original scale data
        """
        if self.scaler_mean is None or self.scaler_std is None:
            return X_norm
            
        return X_norm * self.scaler_std + self.scaler_mean
    
    def _to_tensor(self, X: np.ndarray) -> torch.Tensor:
        """Convert numpy array to PyTorch tensor on the correct device"""
        return torch.tensor(X, dtype=torch.float32).to(self.device)
    
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        """
        Train the autoencoder model
        
        Args:
            X: Training data
            y: Ignored for unsupervised model
        """
        if X.shape[0] == 0:
            raise ValueError("Cannot train on empty dataset")
            
        if X.shape[1] != self.input_dim:
            raise ValueError(f"Expected input dimension {self.input_dim}, got {X.shape[1]}")
            
        start_time = time.time()
        
        # Normalize the data
        X_norm = self._normalize_data(X)
        
        # Create train/validation split if needed
        if self.validation_split > 0 and self.validation_split < 1.0:
            # Shuffle data
            indices = np.arange(X_norm.shape[0])
            np.random.shuffle(indices)
            X_norm = X_norm[indices]
            
            # Split data
            val_size = int(X_norm.shape[0] * self.validation_split)
            X_val = X_norm[:val_size]
            X_train = X_norm[val_size:]
            has_validation = True
        else:
            X_train = X_norm
            X_val = None
            has_validation = False
        
        # Create data loaders
        train_tensor = self._to_tensor(X_train)
        train_dataset = TensorDataset(train_tensor, train_tensor)
        train_loader = DataLoader(
            dataset=train_dataset,
            batch_size=self.batch_size,
            shuffle=True
        )
        
        if has_validation:
            val_tensor = self._to_tensor(X_val)
            val_dataset = TensorDataset(val_tensor, val_tensor)
            val_loader = DataLoader(
                dataset=val_dataset,
                batch_size=self.batch_size,
                shuffle=False
            )
        
        # Set up optimizer
        self.optimizer = optim.Adam(
            self.model.parameters(),
            lr=self.learning_rate,
            weight_decay=self.weight_decay
        )
        
        # Loss function
        criterion = nn.MSELoss(reduction='none')
        
        # Training loop
        best_loss = float('inf')
        patience_counter = 0
        training_history = {"train_loss": [], "val_loss": []}
        
        logger.info(f"Starting autoencoder training for {self.epochs} epochs")
        
        for epoch in range(self.epochs):
            # Training
            self.model.train()
            train_loss = 0.0
            for data, _ in train_loader:
                # Forward pass
                outputs = self.model(data)
                loss = criterion(outputs, data)
                batch_loss = torch.mean(loss)
                
                # Backward and optimize
                self.optimizer.zero_grad()
                batch_loss.backward()
                self.optimizer.step()
                
                train_loss += batch_loss.item() * data.size(0)
            
            train_loss = train_loss / len(train_loader.dataset)
            training_history["train_loss"].append(train_loss)
            
            # Validation
            val_loss = 0.0
            if has_validation:
                self.model.eval()
                with torch.no_grad():
                    for data, _ in val_loader:
                        outputs = self.model(data)
                        loss = criterion(outputs, data)
                        batch_loss = torch.mean(loss)
                        val_loss += batch_loss.item() * data.size(0)
                
                val_loss = val_loss / len(val_loader.dataset)
                training_history["val_loss"].append(val_loss)
                
                # Early stopping check
                if self.early_stopping:
                    if val_loss < best_loss:
                        best_loss = val_loss
                        patience_counter = 0
                    else:
                        patience_counter += 1
                        
                    if patience_counter >= self.patience:
                        logger.info(f"Early stopping at epoch {epoch+1}")
                        break
            
            # Log progress
            if (epoch + 1) % 5 == 0 or epoch == 0 or epoch == self.epochs - 1:
                if has_validation:
                    logger.info(f"Epoch [{epoch+1}/{self.epochs}], "
                               f"Train Loss: {train_loss:.4f}, "
                               f"Val Loss: {val_loss:.4f}")
                else:
                    logger.info(f"Epoch [{epoch+1}/{self.epochs}], "
                               f"Train Loss: {train_loss:.4f}")
        
        # After training, calculate reconstruction errors on training set
        self.model.eval()
        with torch.no_grad():
            # Calculate reconstruction error for each sample
            total_samples = X_norm.shape[0]
            all_errors = np.zeros(total_samples)
            
            # Process in batches to avoid memory issues
            batch_size = 200
            for i in range(0, total_samples, batch_size):
                end_idx = min(i + batch_size, total_samples)
                batch = self._to_tensor(X_norm[i:end_idx])
                outputs = self.model(batch)
                errors = criterion(outputs, batch).mean(dim=1).cpu().numpy()
                all_errors[i:end_idx] = errors
                
            self.reconstruction_errors = all_errors
        
        # Record training stats
        self.training_stats = {
            "n_samples": X.shape[0],
            "n_features": X.shape[1],
            "training_time": time.time() - start_time,
            "epochs_completed": epoch + 1,
            "final_train_loss": train_loss,
            "training_history": training_history
        }
        
        if has_validation:
            self.training_stats["final_val_loss"] = val_loss
            self.training_stats["best_val_loss"] = best_loss
        
        self.trained = True
        logger.info(f"Autoencoder model trained on {X.shape[0]} samples, {X.shape[1]} features")
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores using reconstruction error
        
        Args:
            X: Data to score
            
        Returns:
            Array of anomaly scores (higher = more anomalous)
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Check input dimension
        if X.shape[1] != self.input_dim:
            raise ValueError(f"Expected input dimension {self.input_dim}, got {X.shape[1]}")
        
        # Normalize the data
        X_norm = self._normalize_data(X)
        
        # Calculate reconstruction error
        self.model.eval()
        anomaly_scores = np.zeros(X_norm.shape[0])
        
        # Process in batches to avoid memory issues
        batch_size = 200
        with torch.no_grad():
            for i in range(0, X_norm.shape[0], batch_size):
                end_idx = min(i + batch_size, X_norm.shape[0])
                batch = self._to_tensor(X_norm[i:end_idx])
                outputs = self.model(batch)
                
                # Calculate mean squared error per sample
                errors = torch.mean((outputs - batch) ** 2, dim=1)
                anomaly_scores[i:end_idx] = errors.cpu().numpy()
        
        # Normalize scores based on training set reconstruction errors
        if self.reconstruction_errors is not None:
            # Get statistics from training errors
            mean_error = np.mean(self.reconstruction_errors)
            std_error = np.std(self.reconstruction_errors)
            max_error = np.max(self.reconstruction_errors)
            
            # Normalize to range [0,1] considering the distribution of training errors
            if std_error > 0:
                # Z-score normalization and sigmoid scaling
                z_scores = (anomaly_scores - mean_error) / std_error
                anomaly_scores = 1 / (1 + np.exp(-z_scores))
            else:
                # Simple min-max normalization if std is 0
                anomaly_scores = anomaly_scores / (max_error + 1e-10)
                
        return anomaly_scores
        
    def predict_with_explanation(self, X: np.ndarray) -> Tuple[np.ndarray, List[Dict[str, float]]]:
        """
        Predict with feature-level explanations
        
        Args:
            X: Data to score
            
        Returns:
            Tuple of (scores, explanations)
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Normalize the data
        X_norm = self._normalize_data(X)
        
        # Calculate reconstruction error with feature-level detail
        self.model.eval()
        anomaly_scores = np.zeros(X_norm.shape[0])
        feature_errors = np.zeros((X_norm.shape[0], X_norm.shape[1]))
        
        with torch.no_grad():
            for i in range(0, X_norm.shape[0], self.batch_size):
                end_idx = min(i + self.batch_size, X_norm.shape[0])
                batch = self._to_tensor(X_norm[i:end_idx])
                outputs = self.model(batch)
                
                # Calculate squared error for each feature
                errors = (outputs - batch) ** 2
                feature_errors[i:end_idx] = errors.cpu().numpy()
                
                # Mean error per sample
                anomaly_scores[i:end_idx] = torch.mean(errors, dim=1).cpu().numpy()
                
        # Normalize scores (same as in predict method)
        if self.reconstruction_errors is not None:
            mean_error = np.mean(self.reconstruction_errors)
            std_error = np.std(self.reconstruction_errors)
            max_error = np.max(self.reconstruction_errors)
            
            if std_error > 0:
                z_scores = (anomaly_scores - mean_error) / std_error
                anomaly_scores = 1 / (1 + np.exp(-z_scores))
            else:
                anomaly_scores = anomaly_scores / (max_error + 1e-10)
        
        # Create explanations
        explanations = []
        for i in range(X_norm.shape[0]):
            # Feature importance is proportional to reconstruction error
            feature_scores = {}
            
            # Normalize feature errors to sum to 1
            feature_error_sum = np.sum(feature_errors[i])
            if feature_error_sum > 0:
                normalized_errors = feature_errors[i] / feature_error_sum
            else:
                normalized_errors = np.ones(X_norm.shape[1]) / X_norm.shape[1]
                
            for j in range(X_norm.shape[1]):
                feature_name = self.feature_names[j] if j < len(self.feature_names) else f"feature_{j}"
                feature_scores[feature_name] = float(normalized_errors[j])
                
            explanations.append(feature_scores)
            
        return anomaly_scores, explanations
    
    def get_latent_representation(self, X: np.ndarray) -> np.ndarray:
        """
        Get the latent space representation of the input data
        
        Args:
            X: Input data
            
        Returns:
            Encoded representation in the latent space
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Normalize the data
        X_norm = self._normalize_data(X)
        
        # Encode
        self.model.eval()
        latent_representations = []
        
        with torch.no_grad():
            for i in range(0, X_norm.shape[0], self.batch_size):
                end_idx = min(i + self.batch_size, X_norm.shape[0])
                batch = self._to_tensor(X_norm[i:end_idx])
                encoded = self.model.encode(batch)
                latent_representations.append(encoded.cpu().numpy())
                
        return np.vstack(latent_representations)
    
    def reconstruct(self, X: np.ndarray) -> np.ndarray:
        """
        Reconstruct the input data
        
        Args:
            X: Input data
            
        Returns:
            Reconstructed data
        """
        if not self.trained:
            raise ValueError("Model not trained. Call train() first.")
            
        # Normalize the data
        X_norm = self._normalize_data(X)
        
        # Reconstruct
        self.model.eval()
        reconstructions = []
        
        with torch.no_grad():
            for i in range(0, X_norm.shape[0], self.batch_size):
                end_idx = min(i + self.batch_size, X_norm.shape[0])
                batch = self._to_tensor(X_norm[i:end_idx])
                outputs = self.model(batch)
                reconstructions.append(outputs.cpu().numpy())
                
        reconstructed = np.vstack(reconstructions)
        
        # Denormalize
        return self._denormalize_data(reconstructed)
    
    def get_top_anomalies(self, X: np.ndarray, top_n: int = 10) -> Tuple[np.ndarray, np.ndarray]:
        """
        Get the indices and scores of the top N anomalies
        
        Args:
            X: Data to analyze
            top_n: Number of top anomalies to return
            
        Returns:
            Tuple of (indices, scores) for top anomalies
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
        
        return top_indices, top_scores
    
    def _save_model_data(self, path: str) -> str:
        """
        Save model data to disk
        
        Args:
            path: Directory path
            
        Returns:
            Path to saved model file
        """
        # Save PyTorch model
        model_path = os.path.join(path, "autoencoder.pt")
        torch.save(self.model.state_dict(), model_path)
        
        # Save model architecture
        architecture = {
            "input_dim": self.input_dim,
            "encoding_dim": self.encoding_dim,
            "hidden_layers": self.hidden_layers
        }
        
        arch_path = os.path.join(path, "architecture.json")
        with open(arch_path, "w") as f:
            json.dump(architecture, f, indent=2)
            
        # Save normalization parameters
        if self.scaler_mean is not None and self.scaler_std is not None:
            scaler_path = os.path.join(path, "scaler.json")
            with open(scaler_path, "w") as f:
                json.dump({
                    "mean": self.scaler_mean.tolist(),
                    "std": self.scaler_std.tolist()
                }, f, indent=2)
                
        # Save reconstruction errors from training
        if self.reconstruction_errors is not None:
            errors_path = os.path.join(path, "reconstruction_errors.npy")
            np.save(errors_path, self.reconstruction_errors)
            
        return model_path
        
    @classmethod
    def load(cls, path: str) -> 'AutoencoderModel':
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
            
        # Load architecture
        arch_path = os.path.join(path, "architecture.json")
        with open(arch_path, "r") as f:
            architecture = json.load(f)
            
        # Update config with architecture parameters
        for key, value in architecture.items():
            config.config[key] = value
            
        # Create model instance
        model = cls(config)
        model.input_dim = architecture["input_dim"]
        model.encoding_dim = architecture["encoding_dim"]
        model.hidden_layers = architecture["hidden_layers"]
        
        # Create the autoencoder network
        model.model = Autoencoder(
            input_dim=model.input_dim,
            encoding_dim=model.encoding_dim,
            hidden_layers=model.hidden_layers
        ).to(model.device)
        
        # Load PyTorch model weights
        model_path = os.path.join(path, "autoencoder.pt")
        model.model.load_state_dict(torch.load(model_path, map_location=model.device))
        model.model.eval()  # Set to evaluation mode
        
        # Load normalization parameters
        scaler_path = os.path.join(path, "scaler.json")
        if os.path.exists(scaler_path):
            with open(scaler_path, "r") as f:
                scaler_data = json.load(f)
                model.scaler_mean = np.array(scaler_data["mean"])
                model.scaler_std = np.array(scaler_data["std"])
                
        # Load reconstruction errors
        errors_path = os.path.join(path, "reconstruction_errors.npy")
        if os.path.exists(errors_path):
            model.reconstruction_errors = np.load(errors_path)
        
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
    
    def visualize_latent_space(self, X: np.ndarray, labels: Optional[np.ndarray] = None, 
                              method: str = 'pca', interactive: bool = False) -> Any:
        """
        Visualize the latent space in 2D
        
        Args:
            X: Input data
            labels: Optional labels for coloring points
            method: Dimensionality reduction method ('pca', 'tsne', or 'umap')
            interactive: Whether to create an interactive plot
            
        Returns:
            Plot object
        """
        try:
            import matplotlib.pyplot as plt
            from sklearn.decomposition import PCA
            
            # Get latent representations
            latent = self.get_latent_representation(X)
            
            # Apply dimensionality reduction if needed
            if latent.shape[1] > 2:
                if method == 'pca':
                    # PCA
                    reducer = PCA(n_components=2)
                    latent_2d = reducer.fit_transform(latent)
                elif method == 'tsne':
                    # t-SNE
                    try:
                        from sklearn.manifold import TSNE
                        reducer = TSNE(n_components=2, random_state=42)
                        latent_2d = reducer.fit_transform(latent)
                    except ImportError:
                        logger.warning("t-SNE not available. Using PCA instead.")
                        reducer = PCA(n_components=2)
                        latent_2d = reducer.fit_transform(latent)
                elif method == 'umap':
                    # UMAP
                    try:
                        import umap
                        reducer = umap.UMAP(n_components=2, random_state=42)
                        latent_2d = reducer.fit_transform(latent)
                    except ImportError:
                        logger.warning("UMAP not available. Using PCA instead.")
                        reducer = PCA(n_components=2)
                        latent_2d = reducer.fit_transform(latent)
                else:
                    logger.warning(f"Unknown reduction method: {method}. Using PCA instead.")
                    reducer = PCA(n_components=2)
                    latent_2d = reducer.fit_transform(latent)
            else:
                latent_2d = latent
            
            # Create plot
            if interactive:
                try:
                    import plotly.express as px
                    import plotly.graph_objects as go
                    
                    if labels is not None:
                        fig = px.scatter(
                            x=latent_2d[:, 0], y=latent_2d[:, 1],
                            color=labels,
                            title=f"Latent Space Visualization ({method.upper()})",
                            labels={"color": "Label"},
                            opacity=0.7
                        )
                    else:
                        fig = px.scatter(
                            x=latent_2d[:, 0], y=latent_2d[:, 1],
                            title=f"Latent Space Visualization ({method.upper()})",
                            opacity=0.7
                        )
                        
                    return fig
                    
                except ImportError:
                    logger.warning("Plotly not available. Using Matplotlib instead.")
                    interactive = False
            
            if not interactive:
                plt.figure(figsize=(10, 8))
                
                if labels is not None:
                    scatter = plt.scatter(latent_2d[:, 0], latent_2d[:, 1], c=labels, alpha=0.7)
                    plt.colorbar(scatter, label="Label")
                else:
                    plt.scatter(latent_2d[:, 0], latent_2d[:, 1], alpha=0.7)
                    
                plt.title(f"Latent Space Visualization ({method.upper()})")
                plt.xlabel("Dimension 1")
                plt.ylabel("Dimension 2")
                plt.grid(True, alpha=0.3)
                return plt
                
        except ImportError:
            logger.warning("Matplotlib not available. Cannot create visualization.")
            return None
    
    def plot_reconstruction_errors(self, X: np.ndarray, title: str = "Reconstruction Error Distribution") -> Any:
        """
        Plot the distribution of reconstruction errors
        
        Args:
            X: Data to analyze
            title: Plot title
            
        Returns:
            Plot object
        """
        try:
            import matplotlib.pyplot as plt
            
            # Get reconstruction errors
            scores = self.predict(X)
            
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
            logger.warning("Matplotlib not available. Cannot create plot.")
            return None
    
    def compare_original_vs_reconstructed(self, X: np.ndarray, sample_indices: List[int] = None) -> Any:
        """
        Compare original and reconstructed samples
        
        Args:
            X: Original data
            sample_indices: Indices of samples to compare (default: first 5)
            
        Returns:
            Plot object
        """
        try:
            import matplotlib.pyplot as plt
            
            # Default to first 5 samples if not specified
            if sample_indices is None:
                sample_indices = list(range(min(5, X.shape[0])))
                
            # Get reconstructions
            reconstructed = self.reconstruct(X[sample_indices])
            original = X[sample_indices]
            
            n_samples = len(sample_indices)
            plt.figure(figsize=(15, 3 * n_samples))
            
            for i, (idx, orig, recon) in enumerate(zip(sample_indices, original, reconstructed)):
                plt.subplot(n_samples, 1, i+1)
                
                # Bar plot for feature values
                x = np.arange(len(orig))
                width = 0.35
                
                plt.bar(x - width/2, orig, width, label='Original', alpha=0.7)
                plt.bar(x + width/2, recon, width, label='Reconstructed', alpha=0.7)
                
                # Add feature names if available
                if len(self.feature_names) >= len(orig):
                    plt.xticks(x, self.feature_names, rotation=90)
                
                plt.title(f"Sample {idx}")
                plt.legend()
                plt.tight_layout()
                
            return plt
        except ImportError:
            logger.warning("Matplotlib not available. Cannot create comparison plot.")
            return None
    
    def generate_synthetic_anomalies(self, X: np.ndarray, n_anomalies: int = 10, 
                                   anomaly_factor: float = 3.0) -> np.ndarray:
        """
        Generate synthetic anomalies by modifying normal samples
        
        Args:
            X: Normal data samples
            n_anomalies: Number of anomalies to generate
            anomaly_factor: Factor to multiply standard deviation for anomaly generation
            
        Returns:
            Generated anomalies
        """
        if X.shape[0] < n_anomalies:
            raise ValueError(f"Input data has fewer samples ({X.shape[0]}) than requested anomalies ({n_anomalies})")
            
        # Select random samples to modify
        indices = np.random.choice(X.shape[0], n_anomalies, replace=False)
        base_samples = X[indices].copy()
        
        # Calculate feature means and standard deviations
        feature_means = np.mean(X, axis=0)
        feature_stds = np.std(X, axis=0)
        feature_stds = np.where(feature_stds < 1e-10, 1.0, feature_stds)
        
        # For each sample, randomly modify some features
        for i in range(n_anomalies):
            # Select random features to modify (1 to 3 features)
            n_features_to_modify = np.random.randint(1, 4)
            features_to_modify = np.random.choice(X.shape[1], n_features_to_modify, replace=False)
            
            for j in features_to_modify:
                # Modify feature value by adding or subtracting multiple of standard deviation
                direction = 1 if np.random.random() > 0.5 else -1
                base_samples[i, j] += direction * anomaly_factor * feature_stds[j]
                
        return base_samples


# Helper function to train an autoencoder with cross-validation
def train_autoencoder_with_cv(X: np.ndarray, config: Dict[str, Any], n_splits: int = 5) -> Tuple[AutoencoderModel, Dict[str, Any]]:
    """
    Train an autoencoder with cross-validation
    
    Args:
        X: Training data
        config: Model configuration
        n_splits: Number of cross-validation splits
        
    Returns:
        Tuple of (best_model, cv_results)
    """
    try:
        from sklearn.model_selection import KFold
        
        kf = KFold(n_splits=n_splits, shuffle=True, random_state=42)
        fold_scores = []
        
        for fold, (train_idx, val_idx) in enumerate(kf.split(X)):
            logger.info(f"Training fold {fold+1}/{n_splits}")
            
            # Create and train model
            model = AutoencoderModel(config)
            
            # Update configuration for this fold
            model.config.config["validation_split"] = 0  # Don't split again
            
            # Train on this fold
            model.train(X[train_idx])
            
            # Evaluate on validation fold
            val_scores = model.predict(X[val_idx])
            fold_score = np.mean(val_scores)
            fold_scores.append(fold_score)
            
            logger.info(f"Fold {fold+1} validation score: {fold_score:.4f}")
            
        # Train final model on all data
        logger.info("Training final model on all data")
        final_model = AutoencoderModel(config)
        final_model.train(X)
        
        # Return model and cross-validation results
        cv_results = {
            "fold_scores": fold_scores,
            "mean_score": np.mean(fold_scores),
            "std_score": np.std(fold_scores)
        }
        
        return final_model, cv_results
        
    except ImportError:
        logger.warning("sklearn not available for cross-validation. Training single model.")
        model = AutoencoderModel(config)
        model.train(X)
        return model, {"fold_scores": [], "mean_score": None, "std_score": None}


# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 18:54:12"
__author__ = "Rahul"
