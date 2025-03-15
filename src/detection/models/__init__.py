"""
Anomaly detection models for ASIRA

This package contains various anomaly detection models:
- Statistical methods (Z-score, MAD)
- Machine learning models (Isolation Forest)
- Deep learning models (Autoencoder)
- Ensemble methods

Version: 1.0.0
Last updated: 2025-03-15 18:13:58
Last updated by: Rahul
"""

from src.detection.models.base import BaseModel, ModelConfig
from src.detection.models.statistical import StatisticalModel
from src.detection.models.isolation_forest import IsolationForestModel
from src.detection.models.autoencoder import AutoencoderModel
from src.detection.models.ensemble import EnsembleModel
from src.detection.models.registry import ModelRegistry

__all__ = [
    'BaseModel',
    'ModelConfig',
    'StatisticalModel',
    'IsolationForestModel',
    'AutoencoderModel',
    'EnsembleModel',
    'ModelRegistry'
]
