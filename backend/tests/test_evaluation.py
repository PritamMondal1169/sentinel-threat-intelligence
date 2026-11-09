import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.evaluation import evaluate_correlation


class CorrelationBenchmarkTests(unittest.TestCase):
    def test_benchmark_metrics(self):
        metrics = evaluate_correlation()
        # PRD Section 25 targets: precision >= 0.90, recall >= 0.70
        self.assertGreaterEqual(metrics.precision, 0.90, f"Precision {metrics.precision} below 0.90 target")
        self.assertGreaterEqual(metrics.recall, 0.70, f"Recall {metrics.recall} below 0.70 target")
        self.assertEqual(metrics.false_positives, 0, "No false positive cross-campaign links should be formed")
        self.assertGreaterEqual(metrics.purity, 0.95, "Campaign clusters must be pure")


if __name__ == "__main__":
    unittest.main()

