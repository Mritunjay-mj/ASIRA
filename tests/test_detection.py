"""
Unit tests for ASIRA detection module

These tests verify the functionality of the anomaly detection engine,
feature processors, and machine learning models.

Version: 1.0.0
Last updated: 2025-03-16 12:59:59
Last updated by: Mritunjay-mj
"""

import os
import unittest
import pandas as pd
import numpy as np
import tempfile
import json
from datetime import datetime
from unittest.mock import patch, MagicMock, mock_open

from src.detection.engine import MultiModelDetector, AnomalyDetectionResult, DetectionEngine
from src.detection.processor import LogIngester, LogNormalizer, FeatureExtractor
from src.detection.models import StatisticalDetector, IsolationForestDetector, AutoencoderDetector
from src.detection.features import SessionFeatures, TimeWindowFeatures
from src.detection.pipeline import DetectionPipeline
from src.detection.evaluator import ModelEvaluator
from src.detection.classifier import AnomalyClassifier


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
    
    def test_normalize_malformed_timestamp(self):
        """Test normalization with a malformed timestamp"""
        log_entry = {
            "timestamp": "2025/03/15 invalid-time",
            "source_ip": "192.168.1.100"
        }
        
        # Should not raise exception but use current time
        normalized = self.normalizer.normalize(log_entry)
        
        self.assertIsNotNone(normalized["timestamp"])
        self.assertIsInstance(normalized["timestamp"], float)
    
    def test_normalize_different_log_format(self):
        """Test normalization of different log format"""
        # Windows event log format
        log_entry = {
            "EventTime": "2025-03-15 12:27:24",
            "SourceAddress": "192.168.1.100",
            "TargetAddress": "10.0.0.5",
            "AccountName": "DOMAIN\\admin",
            "EventType": "4624",
            "LogonType": "2"
        }
        
        # Add field mapping to normalizer
        self.normalizer.field_mappings = {
            "EventTime": "timestamp",
            "SourceAddress": "source_ip",
            "TargetAddress": "dest_ip",
            "AccountName": "username"
        }
        
        normalized = self.normalizer.normalize(log_entry)
        
        self.assertEqual(normalized["timestamp"], 1741783644.0)
        self.assertEqual(normalized["source_ip"], "192.168.1.100")
        self.assertEqual(normalized["dest_ip"], "10.0.0.5")
        self.assertEqual(normalized["username"], "DOMAIN\\admin")
    
    def test_normalize_batch(self):
        """Test batch normalization of logs"""
        logs = [
            {
                "timestamp": "2025-03-15 12:27:24",
                "source_ip": "192.168.1.100",
                "username": "admin"
            },
            {
                "timestamp": "2025-03-15 12:28:30",
                "source_ip": "192.168.1.101",
                "username": "user"
            }
        ]
        
        normalized_batch = self.normalizer.normalize_batch(logs)
        
        self.assertEqual(len(normalized_batch), 2)
        self.assertEqual(normalized_batch[0]["timestamp"], 1741783644.0)
        self.assertEqual(normalized_batch[1]["timestamp"], 1741783710.0)  # 2025-03-15 12:28:30


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
    
    def test_extract_features_with_missing_data(self):
        """Test feature extraction with missing data"""
        data = {
            "timestamp": [1741783644.0, 1741783645.0, 1741783646.0],
            "source_ip": ["192.168.1.100", None, "192.168.1.100"],
            "username": ["admin", "user", None],
            "action": ["login", None, "logout"],
            "duration": [0.5, None, 0.8]
        }
        df = pd.DataFrame(data)
        
        result = self.extractor.extract_features(df)
        
        # Verify no NaN values in result
        self.assertFalse(result.isna().any().any())
        
        # Verify missing categorical values were handled
        self.assertIn("source_ip_nan", result.columns)
        self.assertIn("username_nan", result.columns)
        self.assertIn("action_nan", result.columns)
        
        # Verify imputed numerical values
        self.assertAlmostEqual(result["duration"].mean(), 0.65, places=2)  # (0.5 + 0.8) / 2
    
    def test_extract_temporal_features(self):
        """Test extraction of temporal features"""
        # Create data with varying timestamps
        timestamps = [
            datetime(2025, 3, 15, 8, 30, 0).timestamp(),  # 8:30 AM
            datetime(2025, 3, 15, 12, 15, 0).timestamp(),  # 12:15 PM
            datetime(2025, 3, 15, 18, 45, 0).timestamp(),  # 6:45 PM
            datetime(2025, 3, 16, 2, 10, 0).timestamp()   # 2:10 AM next day
        ]
        
        data = {
            "timestamp": timestamps,
            "source_ip": ["192.168.1.100"] * 4,
            "username": ["admin"] * 4
        }
        df = pd.DataFrame(data)
        
        result = self.extractor.extract_features(df)
        
        # Verify temporal features
        self.assertIn("hour", result.columns)
        self.assertIn("day_of_week", result.columns)
        self.assertIn("is_weekend", result.columns)
        self.assertIn("is_business_hours", result.columns)
        
        # Verify correct values
        self.assertEqual(result["hour"].iloc[0], 8)
        self.assertEqual(result["hour"].iloc[1], 12)
        self.assertEqual(result["hour"].iloc[2], 18)
        self.assertEqual(result["hour"].iloc[3], 2)
        
        # 2025-03-15 is a Saturday
        self.assertEqual(result["day_of_week"].iloc[0], 5)  # 5 = Saturday
        self.assertTrue(result["is_weekend"].iloc[0])
        
        # Check business hours
        self.assertTrue(result["is_business_hours"].iloc[1])  # 12:15 PM
        self.assertFalse(result["is_business_hours"].iloc[3])  # 2:10 AM
    
    def test_extract_session_features(self):
        """Test extraction of session-based features"""
        # Enable session features in config
        self.extractor.config["session_features"] = True
        self.extractor.session_window = 60  # 60 second session window
        
        # Create data with session patterns
        data = {
            "timestamp": [
                1741783600.0,  # t0
                1741783610.0,  # t0 + 10s
                1741783620.0,  # t0 + 20s
                1741783680.0,  # t0 + 80s (new session)
                1741783690.0,  # t0 + 90s
                1741784200.0   # t0 + 600s (new session)
            ],
            "source_ip": ["192.168.1.100"] * 6,
            "username": ["admin"] * 6,
            "action": ["login", "read", "read", "login", "read", "login"]
        }
        df = pd.DataFrame(data)
        
        # Add session extractor mock
        session_extractor = SessionFeatures()
        self.extractor.session_extractor = session_extractor
        
        # Mock the session extraction method
        with patch.object(session_extractor, 'extract_session_features') as mock_extract:
            mock_extract.return_value = pd.DataFrame({
                "session_count": [1, 1, 1, 2, 2, 3],
                "actions_in_session": [1, 2, 3, 1, 2, 1],
                "session_duration": [0, 10, 20, 0, 10, 0]
            })
            
            result = self.extractor.extract_features(df)
        
        # Verify session features are included
        self.assertIn("session_count", result.columns)
        self.assertIn("actions_in_session", result.columns)
        self.assertIn("session_duration", result.columns)


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
    
    def test_detection_threshold(self):
        """Test detection threshold behavior"""
        # Create and train on normal data
        normal_data = np.random.normal(0, 1, (100, 4))
        normal_df = pd.DataFrame(normal_data, columns=["f1", "f2", "f3", "f4"])
        self.detector.train(normal_df)
        
        # Create slightly anomalous data
        slight_anomalies = np.random.normal(2, 1, (10, 4))  # Less deviation
        slight_df = pd.DataFrame(slight_anomalies, columns=["f1", "f2", "f3", "f4"])
        slight_df.index = [f"slight_{i}" for i in range(10)]
        
        # Create highly anomalous data
        high_anomalies = np.random.normal(8, 1, (10, 4))  # Higher deviation
        high_df = pd.DataFrame(high_anomalies, columns=["f1", "f2", "f3", "f4"])
        high_df.index = [f"high_{i}" for i in range(10)]
        
        # Test with high threshold
        self.detector.threshold = 0.9
        slight_results = self.detector.detect(slight_df)
        high_results = self.detector.detect(high_df)
        
        # Should detect fewer anomalies in the slight set
        slight_anomaly_count = len([r for r in slight_results if r.is_anomaly])
        high_anomaly_count = len([r for r in high_results if r.is_anomaly])
        
        self.assertLessEqual(slight_anomaly_count, high_anomaly_count)
        
        # Test with low threshold
        self.detector.threshold = 0.3
        slight_results_low = self.detector.detect(slight_df)
        high_results_low = self.detector.detect(high_df)
        
        # Should detect more anomalies with lower threshold
        self.assertGreaterEqual(
            len([r for r in slight_results_low if r.is_anomaly]), 
            slight_anomaly_count
        )
        
        # High anomalies should always be detected
        self.assertEqual(
            len([r for r in high_results_low if r.is_anomaly]), 
            len(high_df)
        )
    
    def test_save_load_model(self):
        """Test saving and loading the detector models"""
        # Create and train on normal data
        normal_data = np.random.normal(0, 1, (100, 4))
        normal_df = pd.DataFrame(normal_data, columns=["f1", "f2", "f3", "f4"])
        self.detector.train(normal_df)
        
        # Create a temporary directory for saving
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "detector.pkl")
            
            # Save the model
            self.detector.save(model_path)
            
            # Verify file exists
            self.assertTrue(os.path.exists(model_path))
            
            # Create a new detector instance
            new_detector = MultiModelDetector(self.config)
            
            # Load the saved model
            new_detector.load(model_path)
            
            # Verify model properties were loaded
            self.assertTrue(new_detector.trained)
            self.assertEqual(new_detector.threshold, self.detector.threshold)
            self.assertEqual(len(new_detector.models), len(self.detector.models))
            
            # Test detection with loaded model
            test_data = np.random.normal(5, 1, (5, 4))
            test_df = pd.DataFrame(test_data, columns=["f1", "f2", "f3", "f4"])
            test_df.index = [f"test_{i}" for i in range(5)]
            
            results = new_detector.detect(test_df)
            
            # Verify detection works
            self.assertGreater(len(results), 0)
    
    def test_individual_models(self):
        """Test individual detection models"""
        # Create and train on normal data
        normal_data = np.random.normal(0, 1, (100, 4))
        normal_df = pd.DataFrame(normal_data, columns=["f1", "f2", "f3", "f4"])
        
        # Initialize and train individual models
        statistical = StatisticalDetector()
        isolation_forest = IsolationForestDetector()
        
        statistical.train(normal_df)
        isolation_forest.train(normal_df)
        
        # Create test data
        test_data = np.random.normal(4, 1, (5, 4))
        test_df = pd.DataFrame(test_data, columns=["f1", "f2", "f3", "f4"])
        
        # Get scores from each model
        stat_scores = statistical.score(test_df)
        iso_scores = isolation_forest.score(test_df)
        
        # Verify scores are in expected range
        for score in stat_scores:
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)
            
        for score in iso_scores:
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)
    
    def test_ensemble_scoring(self):
        """Test ensemble scoring with different weights"""
        # Mock individual model scores
        with patch.object(self.detector, '_score_statistical') as mock_stat:
            with patch.object(self.detector, '_score_isolation_forest') as mock_iso:
                # Set up mock return values
                mock_stat.return_value = np.array([0.9, 0.8, 0.7, 0.6, 0.5])
                mock_iso.return_value = np.array([0.5, 0.6, 0.7, 0.8, 0.9])
                
                # Test with equal weights
                self.detector.model_weights = {"statistical": 1.0, "isolation_forest": 1.0}
                test_df = pd.DataFrame(np.random.rand(5, 4), columns=["f1", "f2", "f3", "f4"])
                ensemble_scores = self.detector._compute_ensemble_scores(test_df)
                
                # Expected scores: average of both models
                expected_scores = np.array([0.7, 0.7, 0.7, 0.7, 0.7])
                np.testing.assert_array_almost_equal(ensemble_scores, expected_scores)
                
                # Test with different weights
                self.detector.model_weights = {"statistical": 2.0, "isolation_forest": 1.0}
                ensemble_scores = self.detector._compute_ensemble_scores(test_df)
                
                # Expected scores: weighted average (2*stat + 1*iso) / 3
                expected_scores = np.array([
                    (2*0.9 + 1*0.5) / 3,
                    (2*0.8 + 1*0.6) / 3,
                    (2*0.7 + 1*0.7) / 3,
                    (2*0.6 + 1*0.8) / 3,
                    (2*0.5 + 1*0.9) / 3
                ])
                np.testing.assert_array_almost_equal(ensemble_scores, expected_scores)


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
    
    def test_csv_file_ingestion(self):
        """Test ingestion of a CSV file"""
        # Create a temporary CSV file
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as temp:
            temp.write(b'timestamp,source_ip,username\n2025-03-15 12:27:24,192.168.1.100,admin')
            temp_path = temp.name
        
        try:
            # Ingest the file
            df = self.ingester.ingest_file(temp_path)
            
            # Verify the DataFrame
            self.assertEqual(len(df), 1)
            self.assertIn("source_ip", df.columns)
            self.assertIn("username", df.columns)
            self.assertEqual(df["username"].iloc[0], "admin")
        finally:
            # Clean up
            os.unlink(temp_path)
    
    def test_syslog_file_ingestion(self):
        """Test ingestion of a syslog file"""
        # Create a temporary syslog file
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as temp:
            temp.write(b'Mar 15 12:27:24 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2\n')
            temp.write(b'Mar 15 12:28:15 server sshd[1235]: Accepted password for user from 10.0.0.2 port 22 ssh2\n')
            temp_path = temp.name
        
        try:
            # Ingest the file
            with patch.object(self.ingester, '_parse_syslog_line') as mock_parse:
                # Set up mock to return parsed logs
                mock_parse.side_effect = [
                    {
                        "timestamp_raw": "Mar 15 12:27:24",
                        "hostname": "server",
                        "process": "sshd",
                        "pid": "1234",
                        "message": "Failed password for admin from 192.168.1.100 port 22 ssh2",
                        "event_type": "auth_failure",
                        "username": "admin",
                        "source_ip": "192.168.1.100"
                    },
                    {
                        "timestamp_raw": "Mar 15 12:28:15",
                        "hostname": "server",
                        "process": "sshd",
                        "pid": "1235",
                        "message": "Accepted password for user from 10.0.0.2 port 22 ssh2",
                        "event_type": "auth_success",
                        "username": "user",
                        "source_ip": "10.0.0.2"
                    }
                ]
                
                df = self.ingester.ingest_file(temp_path)
            
            # Verify the DataFrame
            self.assertEqual(len(df), 2)
            self.assertIn("hostname", df.columns)
            self.assertIn("event_type", df.columns)
            self.assertEqual(df["event_type"].iloc[0], "auth_failure")
            self.assertEqual(df["event_type"].iloc[1], "auth_success")
        finally:
        # Clean up
        os.unlink(temp_path)

def test_stream_ingestion(self):
    """Test ingestion from a data stream"""
    # Create a mock data stream (list of log entries)
    log_stream = [
        {"timestamp": "2025-03-16 13:01:10", "source_ip": "192.168.1.100", "username": "admin", "action": "login"},
        {"timestamp": "2025-03-16 13:01:15", "source_ip": "192.168.1.100", "username": "admin", "action": "view"},
        {"timestamp": "2025-03-16 13:01:20", "source_ip": "192.168.1.101", "username": "user", "action": "login"}
    ]
    
    # Ingest from stream
    df = self.ingester.ingest_stream(log_stream)
    
    # Verify the DataFrame
    self.assertEqual(len(df), 3)
    self.assertIn("timestamp", df.columns)
    self.assertIn("source_ip", df.columns)
    self.assertIn("action", df.columns)
    self.assertEqual(df["username"].iloc[0], "admin")
    self.assertEqual(df["username"].iloc[2], "user")

def test_ingest_with_filters(self):
    """Test ingestion with filtering"""
    # Set up filters
    self.ingester.filters = {
        "source_ip": ["192.168.1.100"],
        "action": ["login"]
    }
    
    # Create test data
    log_data = [
        {"timestamp": "2025-03-16 13:01:10", "source_ip": "192.168.1.100", "username": "admin", "action": "login"},
        {"timestamp": "2025-03-16 13:01:15", "source_ip": "192.168.1.100", "username": "admin", "action": "view"},
        {"timestamp": "2025-03-16 13:01:20", "source_ip": "192.168.1.101", "username": "user", "action": "login"}
    ]
    
    # Ingest with filter
    df = self.ingester.ingest_stream(log_data, apply_filters=True)
    
    # Verify only records matching both filters were included
    self.assertEqual(len(df), 1)
    self.assertEqual(df["source_ip"].iloc[0], "192.168.1.100")
    self.assertEqual(df["action"].iloc[0], "login")

def test_batch_processing(self):
    """Test batch processing of logs"""
    # Create test data with many entries
    log_data = []
    for i in range(250):  # More than batch_size
        log_data.append({
            "timestamp": f"2025-03-16 13:{i//60:02d}:{i%60:02d}",
            "source_ip": f"192.168.1.{i%255}",
            "username": f"user{i%10}",
            "action": "login" if i % 2 == 0 else "view"
        })
    
    # Set small batch size
    self.ingester.batch_size = 100
    
    # Mock the batch processing method
    with patch.object(self.ingester, '_process_batch') as mock_process:
        mock_process.return_value = pd.DataFrame()
        
        # Ingest data
        self.ingester.ingest_stream(log_data)
        
        # Verify batch processing was called multiple times
        self.assertEqual(mock_process.call_count, 3)  # 250 entries / 100 batch size = 3 calls

class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
    """Set up test environment"""
    # Configure the detection engine
    self.config = {
        "detector": {
            "threshold": 0.7,
            "use_statistical": True,
            "use_isolation_forest": True,
            "use_autoencoder": False
        },
        "features": {
            "categorical_features": ["source_ip", "username", "action"],
            "numerical_features": ["duration"],
            "temporal_features": True,
            "session_features": True
        },
        "log_normalizer": {
            "timestamp_formats": ["%Y-%m-%d %H:%M:%S"],
            "ip_fields": ["source_ip", "dest_ip"],
            "username_fields": ["username", "user"]
        },
        "model_path": "/tmp/models"
    }
    
    # Create the engine
    self.engine = DetectionEngine(self.config)

def test_engine_initialization(self):
    """Test engine initialization"""
    self.assertIsNotNone(self.engine.detector)
    self.assertIsNotNone(self.engine.extractor)
    self.assertIsNotNone(self.engine.normalizer)

@patch("src.detection.engine.MultiModelDetector.train")
def test_train_engine(self, mock_train):
    """Test training the detection engine"""
    # Create training data
    train_data = pd.DataFrame({
        "timestamp": pd.to_datetime(["2025-03-16 13:00:00"] * 10),
        "source_ip": ["192.168.1.100"] * 10,
        "username": ["admin"] * 10,
        "action": ["login"] * 10,
        "duration": [0.5] * 10
    })
    
    # Train the engine
    self.engine.train(train_data)
    
    # Verify the feature extractor was called
    mock_train.assert_called_once()

@patch("src.detection.engine.MultiModelDetector.detect")
@patch("src.detection.engine.FeatureExtractor.extract_features")
def test_detect_anomalies(self, mock_extract, mock_detect):
    """Test anomaly detection with the engine"""
    # Create test data
    test_data = pd.DataFrame({
        "timestamp": pd.to_datetime(["2025-03-16 13:00:00"] * 5),
        "source_ip": ["192.168.1.100"] * 5,
        "username": ["admin"] * 5,
        "action": ["login"] * 5
    })
    
    # Mock the extracted features
    mock_features = pd.DataFrame(np.random.rand(5, 4), columns=["f1", "f2", "f3", "f4"])
    mock_extract.return_value = mock_features
    
    # Mock detection results
    mock_results = [
        AnomalyDetectionResult(
            event_id=f"event_{i}",
            anomaly_score=0.8 if i % 2 == 0 else 0.5,
            feature_scores={"f1": 0.8, "f2": 0.7},
            explanation="Test anomaly detection",
            is_anomaly=(i % 2 == 0)  # Every other event is an anomaly
        )
        for i in range(5)
    ]
    mock_detect.return_value = mock_results
    
    # Detect anomalies
    results = self.engine.detect(test_data)
    
    # Verify results
    self.assertEqual(len(results), 5)
    self.assertEqual(len([r for r in results if r.is_anomaly]), 3)  # Events 0, 2, 4 are anomalous

@patch("src.detection.engine.MultiModelDetector.save")
def test_save_model(self, mock_save):
    """Test saving the detection model"""
    self.engine.save_model("/tmp/test_model.pkl")
    mock_save.assert_called_once_with("/tmp/test_model.pkl")

@patch("src.detection.engine.MultiModelDetector.load")
def test_load_model(self, mock_load):
    """Test loading the detection model"""
    self.engine.load_model("/tmp/test_model.pkl")
    mock_load.assert_called_once_with("/tmp/test_model.pkl")

class TestDetectionPipeline(unittest.TestCase):
    def setUp(self):
    """Set up test environment"""
    # Configure the pipeline
    self.config = {
        "ingester": {
            "batch_size": 100,
            "normalizer": {
                "timestamp_formats": ["%Y-%m-%d %H:%M:%S"],
                "ip_fields": ["source_ip", "dest_ip"],
                "username_fields": ["username", "user"]
            }
        },
        "engine": {
            "detector": {
                "threshold": 0.7,
                "use_statistical": True,
                "use_isolation_forest": True
            },
            "features": {
                "categorical_features": ["source_ip", "username", "action"],
                "numerical_features": ["duration"],
                "temporal_features": True
            }
        },
        "classifier": {
            "enabled": True,
            "rules": [
                {
                    "name": "authentication_failure",
                    "description": "Failed authentication attempts",
                    "conditions": ["action == 'login'", "status == 'failure'"],
                    "severity": "medium"
                }
            ]
        }
    }
    
    # Create the pipeline
    self.pipeline = DetectionPipeline(self.config)

@patch("src.detection.pipeline.LogIngester.ingest_file")
@patch("src.detection.pipeline.DetectionEngine.detect")
@patch("src.detection.pipeline.AnomalyClassifier.classify")
def test_pipeline_execution(self, mock_classify, mock_detect, mock_ingest):
    """Test full pipeline execution"""
    # Mock ingested data
    mock_df = pd.DataFrame({
        "timestamp": pd.to_datetime(["2025-03-16 13:00:00"] * 5),
        "source_ip": ["192.168.1.100"] * 5,
        "username": ["admin"] * 5,
        "action": ["login"] * 5,
        "status": ["success", "success", "failure", "failure", "success"]
    })
    mock_ingest.return_value = mock_df
    
    # Mock detection results
    mock_results = [
        AnomalyDetectionResult(
            event_id=f"event_{i}",
            anomaly_score=0.8 if i % 2 == 0 else 0.5,
            feature_scores={"f1": 0.8, "f2": 0.7},
            explanation="Test anomaly detection",
            is_anomaly=(i % 2 == 0),  # Every other event is an anomaly
            source=mock_df.iloc[i].to_dict()
        )
        for i in range(5)
    ]
    mock_detect.return_value = mock_results
    
    # Mock classification
    def classify_side_effect(result):
        result.classification = "authentication_failure" if result.source.get("status") == "failure" else "normal"
        result.severity = "medium" if result.source.get("status") == "failure" else "low"
        return result
    
    mock_classify.side_effect = classify_side_effect
    
    # Execute the pipeline
    results = self.pipeline.process_file("/path/to/logfile.log")
    
    # Verify the pipeline execution
    mock_ingest.assert_called_once_with("/path/to/logfile.log")
    mock_detect.assert_called_once()
    self.assertEqual(mock_classify.call_count, 5)  # Called for each result
    
    # Verify results
    self.assertEqual(len(results), 5)
    
    # Check classifications
    classifications = [r.classification for r in results]
    self.assertEqual(classifications.count("authentication_failure"), 2)  # Two failure statuses
    self.assertEqual(classifications.count("normal"), 3)  # Three success statuses
    
    # Check severities
    severities = [r.severity for r in results]
    self.assertEqual(severities.count("medium"), 2)  # Two events with medium severity
    self.assertEqual(severities.count("low"), 3)  # Three events with low severity

@patch("src.detection.pipeline.DetectionEngine.train")
def test_pipeline_training(self, mock_train):
    """Test training the pipeline"""
    # Create training data
    train_data = pd.DataFrame({
        "timestamp": pd.to_datetime(["2025-03-16 13:00:00"] * 10),
        "source_ip": ["192.168.1.100"] * 10,
        "username": ["admin"] * 10,
        "action": ["login"] * 10,
        "duration": [0.5] * 10
    })
    
    # Train the pipeline
    self.pipeline.train(train_data)
    
    # Verify the engine was trained
    mock_train.assert_called_once_with(train_data)

class TestModelEvaluator(unittest.TestCase):
    def setUp(self):
    """Set up test environment"""
    # Configure the evaluator
    self.config = {
        "metrics": ["precision", "recall", "f1", "roc_auc"],
        "cv_folds": 3,
        "test_size": 0.2
    }
    
    # Create the evaluator
    self.evaluator = ModelEvaluator(self.config)

def test_prepare_evaluation_data(self):
    """Test preparation of evaluation data"""
    # Create normal data
    normal_data = pd.DataFrame({
        "f1": np.random.normal(0, 1, 100),
        "f2": np.random.normal(0, 1, 100),
        "f3": np.random.normal(0, 1, 100)
    })
    normal_data["label"] = 0  # Not anomalous
    
    # Create anomalous data
    anomaly_data = pd.DataFrame({
        "f1": np.random.normal(3, 1, 20),  # Shifted mean
        "f2": np.random.normal(3, 1, 20),
        "f3": np.random.normal(3, 1, 20)
    })
    anomaly_data["label"] = 1  # Anomalous
    
    # Combine data
    all_data = pd.concat([normal_data, anomaly_data])
    
    # Prepare data for evaluation
    X_train, X_test, y_train, y_test = self.evaluator.prepare_data(all_data, label_col="label")
    
    # Verify the splits
    self.assertEqual(len(X_train) + len(X_test), len(all_data))
    self.assertEqual(len(y_train) + len(y_test), len(all_data))
    
    # Verify label column is removed from features
    self.assertNotIn("label", X_train.columns)
    self.assertNotIn("label", X_test.columns)

@patch("src.detection.engine.MultiModelDetector")
def test_evaluate_model(self, mock_detector_class):
    """Test model evaluation"""
    # Set up mock detector
    mock_detector = MagicMock()
    mock_detector_class.return_value = mock_detector
    
    # Mock the train method
    mock_detector.train = MagicMock()
    
    # Mock the detect method to return synthetic results
    def mock_detect_side_effect(data):
        # Return anomaly scores that match the actual labels for test data
        # This will give perfect metrics for a clear test
        results = []
        for i in range(len(data)):
            event_id = f"test_{i}"
            label = test_labels[i]  # Use label from our test data
            results.append(AnomalyDetectionResult(
                event_id=event_id,
                anomaly_score=0.9 if label == 1 else 0.1,  # High score for anomalies
                feature_scores={},
                explanation="Test result",
                is_anomaly=(label == 1)
            ))
        return results
    
    mock_detector.detect = MagicMock(side_effect=mock_detect_side_effect)
    
    # Create synthetic data with labels
    features = np.random.randn(100, 3)  # 100 samples, 3 features
    labels = np.zeros(100)  # All normal by default
    labels[80:] = 1  # Make last 20 samples anomalous
    
    # Convert to DataFrame
    test_data = pd.DataFrame(features, columns=["f1", "f2", "f3"])
    test_data["label"] = labels
    test_labels = labels  # Save for mock_detect to use
    
    # Evaluate the detector
    with patch.object(self.evaluator, 'prepare_data') as mock_prepare:
        # Mock the data preparation to return our test splits
        mock_prepare.return_value = (
            test_data.drop("label", axis=1).iloc[:80],  # Train features
            test_data.drop("label", axis=1).iloc[80:],  # Test features
            test_data["label"].iloc[:80],              # Train labels
            test_data["label"].iloc[80:]               # Test labels
        )
        
        # Run evaluation
        metrics, confusion_matrix = self.evaluator.evaluate(
            detector_config={},
            data=test_data,
            label_col="label"
        )
    
    # Verify the metrics were calculated
    self.assertIn("precision", metrics)
    self.assertIn("recall", metrics)
    self.assertIn("f1", metrics)
    
    # With our mock setup, we should get perfect metrics
    self.assertAlmostEqual(metrics["precision"], 1.0)
    self.assertAlmostEqual(metrics["recall"], 1.0)
    self.assertAlmostEqual(metrics["f1"], 1.0)

class TestAnomalyClassifier(unittest.TestCase):
    def setUp(self):
    """Set up test environment"""
    # Configure rules
    self.rules = [
        {
            "name": "auth_failure",
            "description": "Authentication failure anomaly",
            "conditions": ["action == 'login'", "status == 'failure'"],
            "severity": "high"
        },
        {
            "name": "unusual_access",
            "description": "Access at unusual hours",
            "conditions": ["hour < 6 or hour > 22", "action == 'access'"],
            "severity": "medium"
        },
        {
            "name": "data_exfiltration",
            "description": "Potential data exfiltration",
            "conditions": ["action == 'download'", "bytes > 10000000"],
            "severity": "critical"
        }
    ]
    
    # Create classifier
    self.classifier = AnomalyClassifier({"rules": self.rules})

def test_classify_auth_failure(self):
    """Test classification of authentication failure"""
    # Create an anomaly result
    result = AnomalyDetectionResult(
        event_id="ev_123",
        anomaly_score=0.85,
        feature_scores={},
        explanation="High anomaly score detected",
        is_anomaly=True,
        source={
            "action": "login",
            "status": "failure",
            "timestamp": datetime(2025, 3, 16, 14, 30).timestamp(),
            "source_ip": "192.168.1.100",
            "username": "admin",
            "attempts": 5
        }
    )
    
    # Classify the anomaly
    classified = self.classifier.classify(result)
    
    # Verify classification
    self.assertEqual(classified.classification, "auth_failure")
    self.assertEqual(classified.severity, "high")

def test_classify_unusual_access(self):
    """Test classification of unusual access"""
    # Create an anomaly result for late night access
    result = AnomalyDetectionResult(
        event_id="ev_124",
        anomaly_score=0.75,
        feature_scores={},
        explanation="Unusual timing detected",
        is_anomaly=True,
        source={
            "action": "access",
            "status": "success",
            "timestamp": datetime(2025, 3, 16, 23, 45).timestamp(),  # 11:45 PM
            "source_ip": "192.168.1.101",
            "username": "user",
            "hour": 23  # Late night hour
        }
    )
    
    # Classify the anomaly
    classified = self.classifier.classify(result)
    
    # Verify classification
    self.assertEqual(classified.classification, "unusual_access")
    self.assertEqual(classified.severity, "medium")

def test_classify_multiple_matches(self):
    """Test classification with multiple matching rules"""
    # Create a rule that would match both auth_failure and a new high-priority rule
    self.classifier.rules.append({
        "name": "admin_auth_failure",
        "description": "Admin authentication failure",
        "conditions": ["action == 'login'", "status == 'failure'", "username == 'admin'"],
        "severity": "critical",
        "priority": 100  # Higher priority than default rules
    })
    
    # Create an anomaly result that matches both rules
    result = AnomalyDetectionResult(
        event_id="ev_125",
        anomaly_score=0.90,
        feature_scores={},
        explanation="Admin auth failure detected",
        is_anomaly=True,
        source={
            "action": "login",
            "status": "failure",
            "timestamp": datetime(2025, 3, 16, 15, 20).timestamp(),
            "source_ip": "192.168.1.102",
            "username": "admin",
            "attempts": 10
        }
    )
    
    # Classify the anomaly
    classified = self.classifier.classify(result)
    
    # Verify the higher priority rule was used
    self.assertEqual(classified.classification, "admin_auth_failure")
    self.assertEqual(classified.severity, "critical")

def test_no_matching_rule(self):
    """Test classification with no matching rules"""
    # Create an anomaly result that doesn't match any rule
    result = AnomalyDetectionResult(
        event_id="ev_126",
        anomaly_score=0.72,
        feature_scores={},
        explanation="General anomaly detected",
        is_anomaly=True,
        source={
            "action": "view",
            "status": "success",
            "timestamp": datetime(2025, 3, 16, 12, 30).timestamp(),
            "source_ip": "192.168.1.103",
            "username": "guest"
        }
    )
    
    # Classify the anomaly
    classified = self.classifier.classify(result)
    
    # Verify the default classification
    self.assertEqual(classified.classification, "unknown_anomaly")
    self.assertEqual(classified.severity, "low")
    
    # Original anomaly properties should be preserved
    self.assertEqual(classified.anomaly_score, 0.72)
    self.assertEqual(classified.is_anomaly, True)
    self.assertEqual(classified.event_id, "ev_126")

if name == "main":
    unittest.main()
