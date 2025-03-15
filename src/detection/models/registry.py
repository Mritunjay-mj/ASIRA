"""
Model Registry for Anomaly Detection Models

Provides centralized registration, creation, and tracking of anomaly detection models
with versioning and persistence management

Version: 1.0.0
Last updated: 2025-03-15 19:01:16
Last updated by: Rahul
"""

import os
import json
import time
import uuid
import shutil
from typing import Dict, List, Any, Optional, Type, Union, Tuple
from pathlib import Path
import importlib
from datetime import datetime

from src.common.logging_config import get_logger
from src.detection.models.base import BaseModel, ModelConfig

# Initialize logger
logger = get_logger("asira.detection.models.registry")

class ModelRegistry:
    """
    Registry for anomaly detection models
    
    Handles registration, creation, discovery, and versioning of models
    """
    
    def __init__(self, models_dir: str = "models"):
        """
        Initialize model registry
        
        Args:
            models_dir: Directory for model storage
        """
        self.models_dir = models_dir
        self.registered_models: Dict[str, Type[BaseModel]] = {}
        self.model_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Create models directory if it doesn't exist
        os.makedirs(self.models_dir, exist_ok=True)
        
        # Initialize with available models
        self._register_builtin_models()
        self._load_model_metadata()
    
    def _register_builtin_models(self) -> None:
        """Register the built-in model types"""
        try:
            # Import models - handle imports here to avoid circular imports
            from src.detection.models.statistical import StatisticalModel
            from src.detection.models.isolation_forest import IsolationForestModel
            from src.detection.models.autoencoder import AutoencoderModel
            from src.detection.models.ensemble import EnsembleModel
            
            # Register models
            self.register_model("statistical", StatisticalModel)
            self.register_model("isolation_forest", IsolationForestModel)
            self.register_model("autoencoder", AutoencoderModel)
            self.register_model("ensemble", EnsembleModel)
            
        except ImportError as e:
            logger.warning(f"Could not import all model types: {e}")
    
    def _load_model_metadata(self) -> None:
        """Load metadata for all saved models"""
        try:
            # Get all model directories
            for item in os.listdir(self.models_dir):
                item_path = os.path.join(self.models_dir, item)
                
                # Check if it's a directory
                if os.path.isdir(item_path):
                    metadata_path = os.path.join(item_path, "metadata.json")
                    config_path = os.path.join(item_path, "config.json")
                    
                    # Load metadata if exists
                    if os.path.exists(metadata_path) and os.path.exists(config_path):
                        try:
                            with open(metadata_path, "r") as f:
                                metadata = json.load(f)
                                
                            with open(config_path, "r") as f:
                                config = json.load(f)
                                
                            model_id = config.get("model_id", item)
                            self.model_metadata[model_id] = {
                                **metadata,
                                "config": config,
                                "model_path": item_path
                            }
                        except Exception as e:
                            logger.warning(f"Error loading model metadata for {item}: {e}")
        except Exception as e:
            logger.error(f"Error loading model metadata: {e}")
    
    def register_model(self, model_type: str, model_class: Type[BaseModel]) -> None:
        """
        Register a model class
        
        Args:
            model_type: Type identifier for the model
            model_class: Model class (must inherit from BaseModel)
        """
        if not issubclass(model_class, BaseModel):
            raise ValueError(f"Model class {model_class.__name__} must inherit from BaseModel")
            
        self.registered_models[model_type] = model_class
        logger.info(f"Registered model type: {model_type}")
    
    def create_model(self, config: Union[Dict[str, Any], ModelConfig]) -> BaseModel:
        """
        Create a model instance from configuration
        
        Args:
            config: Model configuration
            
        Returns:
            Model instance
        """
        # Convert dict to ModelConfig if needed
        if isinstance(config, dict):
            model_config = ModelConfig(config)
        else:
            model_config = config
            
        model_type = model_config.model_type
        
        if model_type not in self.registered_models:
            raise ValueError(f"Unknown model type: {model_type}")
            
        model_class = self.registered_models[model_type]
        return model_class(model_config)
    
    def save_model(self, model: BaseModel, description: str = "") -> str:
        """
        Save a model to the registry
        
        Args:
            model: Model to save
            description: Optional description
            
        Returns:
            Path to saved model
        """
        # Create directory for model
        model_id = model.config.model_id
        version = model.config.version
        model_dir = os.path.join(self.models_dir, f"{model_id}_v{version.replace('.', '_')}")
        os.makedirs(model_dir, exist_ok=True)
        
        # Save model
        model_path = model.save(model_dir)
        
        # Update metadata
        creation_time = datetime.now().isoformat()
        self.model_metadata[model_id] = {
            "model_id": model_id,
            "model_type": model.config.model_type,
            "version": version,
            "description": description,
            "created_at": creation_time,
            "saved_at": creation_time,
            "model_path": model_dir,
            "trained": model.trained,
            "config": model.config.to_dict()
        }
        
        logger.info(f"Saved model {model_id} version {version} to {model_dir}")
        
        return model_dir
    
    def load_model(self, model_id: str, version: Optional[str] = None) -> BaseModel:
        """
        Load a model from the registry
        
        Args:
            model_id: Model ID
            version: Optional version (loads latest if None)
            
        Returns:
            Loaded model
        """
        # Check if model exists
        if model_id not in self.model_metadata:
            raise ValueError(f"Model {model_id} not found in registry")
            
        # Get model metadata
        metadata = self.model_metadata[model_id]
        model_type = metadata["model_type"]
        
        if model_type not in self.registered_models:
            raise ValueError(f"Unknown model type: {model_type}")
            
        # Get model path
        model_path = metadata["model_path"]
        
        # Load model
        model_class = self.registered_models[model_type]
        return model_class.load(model_path)
    
    def get_model_info(self, model_id: str) -> Dict[str, Any]:
        """
        Get information about a model
        
        Args:
            model_id: Model ID
            
        Returns:
            Model metadata
        """
        if model_id not in self.model_metadata:
            raise ValueError(f"Model {model_id} not found in registry")
            
        return self.model_metadata[model_id]
    
    def list_models(self, model_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List all models in the registry
        
        Args:
            model_type: Optional filter by model type
            
        Returns:
            List of model metadata
        """
        models = []
        
        for model_id, metadata in self.model_metadata.items():
            if model_type is None or metadata.get("model_type") == model_type:
                models.append(metadata)
                
        return models
    
    def delete_model(self, model_id: str) -> bool:
        """
        Delete a model from the registry
        
        Args:
            model_id: Model ID
            
        Returns:
            True if model was deleted
        """
        if model_id not in self.model_metadata:
            raise ValueError(f"Model {model_id} not found in registry")
            
        # Get model path
        model_path = self.model_metadata[model_id]["model_path"]
        
        # Delete directory
        try:
            shutil.rmtree(model_path)
            # Remove from metadata
            del self.model_metadata[model_id]
            logger.info(f"Deleted model {model_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting model {model_id}: {e}")
            return False
    
    def update_model_metadata(self, model_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update model metadata
        
        Args:
            model_id: Model ID
            updates: Metadata updates
            
        Returns:
            True if successful
        """
        if model_id not in self.model_metadata:
            raise ValueError(f"Model {model_id} not found in registry")
            
        # Update metadata
        self.model_metadata[model_id].update(updates)
        
        # Update metadata file
        try:
            model_path = self.model_metadata[model_id]["model_path"]
            metadata_path = os.path.join(model_path, "metadata.json")
            
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
                
            # Update fields
            metadata.update(updates)
            
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
                
            logger.info(f"Updated metadata for model {model_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating metadata for model {model_id}: {e}")
            return False
    
    def export_model(self, model_id: str, export_path: str) -> str:
        """
        Export a model to a specified path
        
        Args:
            model_id: Model ID
            export_path: Export directory
            
        Returns:
            Path to exported model
        """
        if model_id not in self.model_metadata:
            raise ValueError(f"Model {model_id} not found in registry")
            
        # Get model path
        model_path = self.model_metadata[model_id]["model_path"]
        
        # Create export directory
        os.makedirs(export_path, exist_ok=True)
        export_model_path = os.path.join(export_path, model_id)
        
        # Copy model files
        shutil.copytree(model_path, export_model_path, dirs_exist_ok=True)
        
        logger.info(f"Exported model {model_id} to {export_model_path}")
        
        return export_model_path
    
    def import_model(self, import_path: str) -> str:
        """
        Import a model from a specified path
        
        Args:
            import_path: Path to model directory
            
        Returns:
            Imported model ID
        """
        # Check if path exists
        if not os.path.exists(import_path) or not os.path.isdir(import_path):
            raise ValueError(f"Import path {import_path} does not exist or is not a directory")
            
        # Check for required files
        metadata_path = os.path.join(import_path, "metadata.json")
        config_path = os.path.join(import_path, "config.json")
        
        if not os.path.exists(metadata_path) or not os.path.exists(config_path):
            raise ValueError(f"Import path {import_path} does not contain required metadata and config files")
            
        # Load metadata and config
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
            
        with open(config_path, "r") as f:
            config = json.load(f)
            
        model_id = config.get("model_id", os.path.basename(import_path))
        version = config.get("version", "1.0.0")
        
        # Create directory for imported model
        model_dir = os.path.join(self.models_dir, f"{model_id}_v{version.replace('.', '_')}")
        
        # Check if model already exists
        if os.path.exists(model_dir):
            model_dir = os.path.join(self.models_dir, f"{model_id}_imported_{int(time.time())}")
            
        # Copy model files
        shutil.copytree(import_path, model_dir)
        
        # Update metadata
        metadata["model_path"] = model_dir
        metadata["imported_at"] = datetime.now().isoformat()
        
        self.model_metadata[model_id] = {
            **metadata,
            "config": config
        }
        
        logger.info(f"Imported model {model_id} from {import_path}")
        
        return model_id
    
    def create_ensemble(self, model_ids: List[str], ensemble_config: Dict[str, Any] = None) -> BaseModel:
        """
        Create an ensemble from existing models
        
        Args:
            model_ids: List of model IDs to include
            ensemble_config: Optional ensemble configuration
            
        Returns:
            Ensemble model
        """
        # Check if models exist
        for model_id in model_ids:
            if model_id not in self.model_metadata:
                raise ValueError(f"Model {model_id} not found in registry")
        
        # Load models
        models = {}
        for model_id in model_ids:
            models[model_id] = self.load_model(model_id)
        
        # Create ensemble configuration
        if ensemble_config is None:
            ensemble_config = {}
        
        ensemble_config["model_type"] = "ensemble"
        ensemble_config["model_id"] = ensemble_config.get("model_id", f"ensemble_{uuid.uuid4().hex[:8]}")
        
        # Import here to avoid circular imports
        from src.detection.models.ensemble import create_ensemble_from_models
        
        # Create ensemble
        ensemble_method = ensemble_config.get("ensemble_method", "average")
        model_weights = ensemble_config.get("model_weights", {})
        
        ensemble = create_ensemble_from_models(models, ensemble_method, model_weights)
        
        # Add original model IDs to config
        ensemble.config.config["source_models"] = model_ids
        
        return ensemble
    
    def get_model_versions(self, model_id: str) -> List[str]:
        """
        Get all versions of a model
        
        Args:
            model_id: Model ID
            
        Returns:
            List of version strings
        """
        versions = []
        prefix = f"{model_id}_v"
        
        # Look for directories matching the pattern model_id_v*
        for item in os.listdir(self.models_dir):
            if item.startswith(prefix) and os.path.isdir(os.path.join(self.models_dir, item)):
                version_str = item[len(prefix):].replace('_', '.')
                versions.append(version_str)
                
        return sorted(versions)
    
    def get_latest_version(self, model_id: str) -> str:
        """
        Get latest version of a model
        
        Args:
            model_id: Model ID
            
        Returns:
            Latest version string
        """
        versions = self.get_model_versions(model_id)
        if not versions:
            return None
        return versions[-1]
    
    def compare_models(self, model_id1: str, model_id2: str) -> Dict[str, Any]:
        """
        Compare two models
        
        Args:
            model_id1: First model ID
            model_id2: Second model ID
            
        Returns:
            Comparison results
        """
        if model_id1 not in self.model_metadata:
            raise ValueError(f"Model {model_id1} not found in registry")
            
        if model_id2 not in self.model_metadata:
            raise ValueError(f"Model {model_id2} not found in registry")
            
        metadata1 = self.model_metadata[model_id1]
        metadata2 = self.model_metadata[model_id2]
        
        # Compare metadata
        comparison = {
            "model_id1": model_id1,
            "model_id2": model_id2,
            "model_type1": metadata1.get("model_type"),
            "model_type2": metadata2.get("model_type"),
            "version1": metadata1.get("version"),
            "version2": metadata2.get("version"),
            "created_at1": metadata1.get("created_at"),
            "created_at2": metadata2.get("created_at")
        }
        
        # Compare training stats if available
        stats1 = metadata1.get("training_stats", {})
        stats2 = metadata2.get("training_stats", {})
        
        comparison["training_stats_diff"] = {
            key: {"model1": stats1.get(key), "model2": stats2.get(key)}
            for key in set(stats1.keys()).union(stats2.keys())
        }
        
        return comparison


# Global model registry instance
_model_registry = None

def get_model_registry(models_dir: Optional[str] = None) -> ModelRegistry:
    """
    Get the global model registry instance
    
    Args:
        models_dir: Optional models directory
        
    Returns:
        Model registry instance
    """
    global _model_registry
    
    if _model_registry is None:
        if models_dir is None:
            # Default to "models" directory in current working directory
            models_dir = "models"
        _model_registry = ModelRegistry(models_dir)
        
    return _model_registry


# Convenience functions using the global registry

def register_model(model_type: str, model_class: Type[BaseModel]) -> None:
    """
    Register a model class in the global registry
    
    Args:
        model_type: Model type identifier
        model_class: Model class
    """
    registry = get_model_registry()
    registry.register_model(model_type, model_class)

def create_model(config: Union[Dict[str, Any], ModelConfig]) -> BaseModel:
    """
    Create a model using the global registry
    
    Args:
        config: Model configuration
        
    Returns:
        Model instance
    """
    registry = get_model_registry()
    return registry.create_model(config)

def save_model(model: BaseModel, description: str = "") -> str:
    """
    Save a model using the global registry
    
    Args:
        model: Model to save
        description: Optional description
        
    Returns:
        Path to saved model
    """
    registry = get_model_registry()
    return registry.save_model(model, description)

def load_model(model_id: str, version: Optional[str] = None) -> BaseModel:
    """
    Load a model using the global registry
    
    Args:
        model_id: Model ID
        version: Optional version
        
    Returns:
        Loaded model
    """
    registry = get_model_registry()
    return registry.load_model(model_id, version)

def list_models(model_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List models using the global registry
    
    Args:
        model_type: Optional model type filter
        
    Returns:
        List of model metadata
    """
    registry = get_model_registry()
    return registry.list_models(model_type)


# Module version information
__version__ = "1.0.0"
__last_updated__ = "2025-03-15 19:01:16"
__author__ = "Rahul"
