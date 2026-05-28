import unittest
import numpy as np
from drift_predictor.drift import DriftPredictorService
from semantic_matcher.similarity import SemanticMatcherService

class TestAIServices(unittest.TestCase):
    def setUp(self):
        self.drift_service = DriftPredictorService()
        self.similarity_service = SemanticMatcherService()

    def test_drift_predictor_format_and_bounds(self):
        # Generate clean 90-day trajectory (slowly decaying compliance score)
        decaying_scores = [max(0.0, 100.0 - (i * 0.5)) for i in range(90)]
        
        predictions = self.drift_service.predict_drift(decaying_scores)
        
        # Verify forecast keys
        self.assertIn("forecast_7_days", predictions)
        self.assertIn("forecast_14_days", predictions)
        self.assertIn("forecast_30_days", predictions)
        
        # Verify predictions are bounded [0, 100]
        for key, val in predictions.items():
            self.assertTrue(0.0 <= val <= 100.0, f"Forecast {key} value {val} out of bounds.")

    def test_drift_predictor_invalid_length(self):
        short_scores = [90.0] * 80
        with self.assertRaises(ValueError):
            self.drift_service.predict_drift(short_scores)

    def test_semantic_matcher_merging_logic(self):
        existing_devices = [
            {"id": "device-uuid-1", "canonical_name": "DESKTOP-A1B2C3"},
            {"id": "device-uuid-2", "canonical_name": "LAPTOP-EUD-MAIN"},
        ]

        # Case 1: Extremely high match (should auto-merge)
        res_exact = self.similarity_service.evaluate_match("DESKTOP-A1B2C3", existing_devices)
        self.assertEqual(res_exact["action"], "AUTO_MERGE")
        self.assertEqual(res_exact["matched_device_id"], "device-uuid-1")

        # Case 2: Clean separation for completely distinct devices
        res_distinct = self.similarity_service.evaluate_match("MACBOOK-PRO-RETINA", existing_devices)
        # Even with hash-based mock seed fallback, distinct labels will not hit >0.88 similarity
        self.assertIn(res_distinct["action"], ["HUMAN_QUEUE", "NEW_DEVICE"])

if __name__ == "__main__":
    unittest.main()
