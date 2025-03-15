"""
Unit tests for ASIRA detection module

These tests verify the functionality of the anomaly detection engine,
feature processors, and machine learning models.

Version: 1.0.0
Last updated: 2025-03-15 12:27:24
Last updated by: Mritunjay-mj
"""

import os
import unittest
import pandas as pd
import numpy as np
import tempfile
from unittest.mock import patch, MagicMock

from src.detection.engine import MultiModelDetector, AnomalyDetectionResult
from src.detection.processor import LogIngester, LogNormalizer, FeatureExtractor


class TestLogNormalizer(unittest.TestCase):
    """Test cases for the LogNormalizer class"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            "timestamp_formats": ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ"],
            "ip_fields": ["source_ip", "dest_ip", "ip"],
            "username_fields": ["username", "user", "account"]
        }
        self.normalizer = LogNormalizer(self.config)
    
    def test_normalize_complete_log(self):
        """Test normalization of a complete log entry"""
        log_entry = {
            "timestamp": "2025-03-15 12:27:24",
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "username": "admin",
            "action": "login",
            "status": "success"
        }
        
        normalized = self.normalizer.normalize(log_entry)
        
        self.assertEqual(normalized["timestamp"], 1741783644.0)  # Timestamp for 2025-03-15 12:27:24
        self.assertEqual(normalized["source_ip"], "192.168.1.100")
        self.assertEqual(normalized["dest_ip"], "10.0.0.5")
        self.assertEqual(normalized["username"], "admin")
        self.assertEqual(normalized["action"], "login")
        self.assertEqual(normalized["status"], "success")
    
    def test_normalize_partial_log(self):
        """Test normalization of a partial log entry"""
        log_entry = {
            "time": "2025-03-15T12:27:24.000Z",
            "ip": "192.168.1.100",
            "user": "admin"
        }
        
        normalized = self.normalizer.normalize(log_entry)
        
        self.assertEqual(normalized["timestamp"], 1741783644.0)  # Timestamp for 2025-03-15 12:27:24
        self.assertEqual(normalized["source_ip"], "192.168.1.100")
        self.assertEqual(normalized["username"], "admin")
    
    def test_normalize_numeric_timestamp(self):
        """Test normalization with a numeric timestamp"""
        timestamp = 1741783644.0  # 2025-03-15 12:27:24
        log_entry = {
            "timestamp": timestamp,
            "source_ip": "192.168.1.100"
        }
        
        normalized = self.normalizer.normalize(log_entry)
        
        self.assertEqual(normalized["timestamp"], timestamp)


class TestFeatureExtractor(unittest.TestCase):
    """Test cases for the FeatureExtractor class"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            "categorical_features": ["source_ip", "username", "action"],
            "numerical_features": ["duration"],
            "temporal_features": True
        }
        self.extractor = FeatureExtractor(self.config)
    
    def test_extract_features_empty_df(self):
        """Test feature extraction with empty DataFrame"""
        df = pd.DataFrame()
        
        result = self.extractor.extract_features(df)
        
        self.assertTrue(result.empty)
    
    def test_extract_features(self):
        """Test feature extraction from log entries"""
        data = {
            "timestamp": [1741783644.0, 1741783645.0, 1741783646.0],
            "source_ip": ["192.168.1.100", "192.168.1.101", "192.168.1.100"],
            "username": ["admin", "user", "admin"],
            "action": ["login", "read", "logout"],
            "duration": [0.5, 1.2, 0.8]
        }
        df = pd.DataFrame(data)
        
        result = self.extractor.extract_features(df)
        
        # Verify the result contains expected columns
        self.assertIn("duration", result.columns)
        self.assertIn("hour", result.columns)  # Temporal feature
        
        # One-hot encoded categorical features
        self.assertIn("source_ip_192.168.1.100", result.columns)
        self.assertIn("source_ip_192.168.1.101", result.columns)
        self.assertIn("username_admin", result.columns)
        self.assertIn("action_login", result.columns)


class TestMultiModelDetector(unittest.TestCase):
    """Test cases for the MultiModelDetector class"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            "threshold": 0.7,
            "use_statistical": True,
            "use_isolation_forest": True,
            "use_autoencoder": False,  # Disable for testing
            "feature_names": ["f1", "f2", "f3", "f4"],
            "model_weights": {
                "statistical": 1.0,
                "isolation_forest": 1.0
            }
        }
        self.detector = MultiModelDetector(self.config)
    
    def test_initialization(self):
        """Test detector initialization"""
        self.assertEqual(self.detector.threshold, 0.7)
        self.assertIn("statistical", self.detector.models)
        self.assertIn("isolation_forest", self.detector.models)
        self.assertNotIn("autoencoder", self.detector.models)
    
    @patch("sklearn.ensemble.IsolationForest.fit")
    def test_train(self, mock_fit):
        """Test training the detector models"""
        # Create synthetic normal data
        data = np.random.rand(100, 4)  # 100 samples, 4 features
        df = pd.DataFrame(data, columns=["f1", "f2", "f3", "f4"])
        
        self.detector.train(df)
        
        # Verify statistical model has been trained
        self.assertIsNotNone(self.detector.models["statistical"]["mean"])
        self.assertIsNotNone(self.detector.models["statistical"]["std"])
        
        # Verify isolation forest was trained
        mock_fit.assert_called_once()
        
        # Verify detector is marked as trained
        self.assertTrue(self.detector.trained)
    
    def test_detect_anomalies(self):
        """Test anomaly detection"""
        # Create and train on normal data
        normal_data = np.random.normal(0, 1, (100, 4))  # 100 samples, 4 features
        normal_df = pd.DataFrame(normal_data, columns=["f1", "f2", "f3", "f4"])
        self.detector.train(normal_df)
        
        # Create anomalous data (outliers)
        anomalous_data = np.random.normal(5, 1, (10, 4))  # 10 samples, shifted mean
        anomalous_df = pd.DataFrame(anomalous_data, columns=["f1", "f2", "f3", "f4"])
        
        # Add event IDs as index
        anomalous_df.index = [f"event_{i}" for i in range(10)]
        
        # Detect anomalies
        results = self.detector.detect(anomalous_df)
        
        # Verify we got anomaly detections
        self.assertGreater(len(results), 0)
        
        # Verify result structure
        first_result = results[0]
        self.assertIsInstance(first_result, AnomalyDetectionResult)
        self.assertTrue(hasattr(first_result, "event_id"))
        self.assertTrue(hasattr(first_result, "anomaly_score"))
        self.assertTrue(hasattr(first_result, "explanation"))
        
        # Verify anomaly scores are in the expected range
        for result in results:
            self.assertGreaterEqual(result.anomaly_score, 0.0)
            self.assertLessEqual(result.anomaly_score, 1.0)


class TestLogIngester(unittest.TestCase):
    """Test cases for the LogIngester class"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = {
            "batch_size": 100,
            "normalizer": {
                "timestamp_formats": ["%Y-%m-%d %H:%M:%S"],
                "ip_fields": ["source_ip", "dest_ip", "ip"],
                "username_fields": ["username", "user"]
            }
        }
        self.ingester = LogIngester(self.config)
    
    def test_determine_format(self):
        """Test format determination from file extension"""
        self.assertEqual(self.ingester._determine_format("logs.json"), "json")
        self.assertEqual(self.ingester._determine_format("data.csv"), "csv")
        self.assertEqual(self.ingester._determine_format("syslog.log"), "syslog")
        self.assertEqual(self.ingester._determine_format("events.evtx"), "windows_event")
        self.assertEqual(self.ingester._determine_format("unknown.xyz"), "unknown")
    
    def test_parse_syslog_line(self):
        """Test parsing of a syslog line"""
        line = "Mar 15 12:27:24 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2"
        
        result = self.ingester._parse_syslog_line(line)
        
        self.assertEqual(result["timestamp_raw"], "Mar 15 12:27:24")
        self.assertEqual(result["hostname"], "server")
        self.assertEqual(result["process"], "sshd")
        self.assertEqual(result["pid"], "1234")
        self.assertEqual(result["event_type"], "auth_failure")
        self.assertEqual(result["username"], "admin")
        self.assertEqual(result["source_ip"], "192.168.1.100")
    
    def test_json_file_ingestion(self):
        """Test ingestion of a JSON file"""
        # Create a temporary JSON file
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp:
            temp.write(b'[{"timestamp": "2025-03-15 12:27:24", "source_ip": "192.168.1.100", "username": "admin"}]')
            temp_path = temp.name
        
        try:
            # Ingest the file
            df = self.ingester.ingest_file(temp_path)
            
            # Verify the DataFrame
            self.assertEqual(len(df), 1)
            self.assertIn("source_ip", df.columns)
            self.assertIn("username", df.columns)
        finally:
            # Clean up
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
