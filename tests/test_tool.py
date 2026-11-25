import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from iqtool.analysis import analyze_iq, load_iq
from iqtool.algorithms import analyze_samples
from iqtool.cli import main
from iqtool.providers import _openai_compatible_reply


class IQAnalysisTests(unittest.TestCase):
    def test_baseline_algorithm_recovers_two_tone_power_and_rms(self):
        sample_count = 1024
        indices = np.arange(sample_count)
        samples = (
            2 * np.exp(2j * np.pi * 64 * indices / sample_count)
            + np.exp(-2j * np.pi * 128 * indices / sample_count)
        )

        report = analyze_samples(samples, sample_rate=1024.0)

        self.assertAlmostEqual(report["metrics"]["rms_magnitude"], np.sqrt(5.0))
        self.assertEqual(
            [peak["frequency"] for peak in report["spectral_peaks"][:2]],
            [64.0, -128.0],
        )
        self.assertAlmostEqual(report["spectral_peaks"][0]["relative_power"], 0.8)
        self.assertAlmostEqual(report["spectral_peaks"][1]["relative_power"], 0.2)
        self.assertAlmostEqual(report["metrics"]["spectral_entropy_bits"], 0.7219280949)

    def test_baseline_algorithm_handles_zero_signal_without_nan(self):
        report = analyze_samples(np.zeros(16, dtype=np.complex128))

        self.assertEqual(report["metrics"]["rms_magnitude"], 0.0)
        self.assertEqual(report["metrics"]["crest_factor"], 0.0)
        self.assertEqual(report["metrics"]["spectral_entropy_bits"], 0.0)
        self.assertEqual(report["spectral_peaks"], [])

    def test_baseline_algorithm_rejects_non_complex_and_multidimensional_data(self):
        with self.assertRaisesRegex(ValueError, "complex-valued"):
            analyze_samples(np.ones(4, dtype=np.float64))
        with self.assertRaisesRegex(ValueError, "one-dimensional"):
            analyze_samples(np.ones((2, 2), dtype=np.complex128))

    def test_baseline_algorithm_rejects_non_finite_samples_and_sample_rate(self):
        with self.assertRaisesRegex(ValueError, "NaN or infinite"):
            analyze_samples(np.array([1 + 0j, complex(float("nan"), 0)]))
        with self.assertRaisesRegex(ValueError, "finite positive"):
            analyze_samples(np.ones(4, dtype=np.complex128), sample_rate=float("inf"))

    def test_reads_csv_with_header_and_finds_known_tone(self):
        sample_count = 1024
        sample_rate = 1024.0
        sample_indices = np.arange(sample_count)
        signal = np.exp(2j * np.pi * 64 * sample_indices / sample_rate)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.csv"
            np.savetxt(
                path,
                np.column_stack((signal.real, signal.imag)),
                delimiter=",",
                header="I,Q",
                comments="",
            )
            report = analyze_iq(path, sample_rate)

        self.assertEqual(report["input"]["sample_count"], sample_count)
        self.assertAlmostEqual(report["spectral_peaks"][0]["frequency"], 64.0)
        self.assertEqual(report["spectral_peaks"][0]["unit"], "Hz")
        self.assertAlmostEqual(report["metrics"]["rms_magnitude"], 1.0)

    def test_reads_complex_npy(self):
        signal = np.array([1 + 2j, 2 + 3j, 3 + 4j], dtype=np.complex128)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.npy"
            np.save(path, signal)
            np.testing.assert_array_equal(load_iq(path), signal)

    def test_rejects_non_finite_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.csv"
            path.write_text("I,Q\n1,0\nnan,1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "NaN or infinite"):
                load_iq(path)

    def test_requires_positive_sample_rate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.csv"
            path.write_text("1,0\n0,1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "finite positive"):
                analyze_iq(path, 0)

    def test_cli_writes_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.csv"
            output = Path(directory) / "report.json"
            path.write_text("I,Q\n1,0\n0,1\n-1,0\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve().parents[1] / "main.py"),
                    "analyze",
                    str(path),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            report = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["input"]["sample_count"], 3)

    def test_cli_will_not_overwrite_iq_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.csv"
            original = "1,0\n0,1\n"
            path.write_text(original, encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                result = main(["analyze", str(path), "--output", str(path)])

            self.assertEqual(result, 2)
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_openai_compatible_provider_sends_report_messages(self):
        response_body = b'{"choices":[{"message":{"content":"Measured peak noted."}}]}'
        messages = [
            {"role": "system", "content": "Defensive analysis only."},
            {"role": "user", "content": "RMS: 0.5"},
        ]
        with patch(
            "iqtool.providers.urlopen", return_value=io.BytesIO(response_body)
        ) as mocked_urlopen:
            answer = _openai_compatible_reply(
                "https://example.invalid/v1", "test-model", "test-key", messages
            )

        self.assertEqual(answer, "Measured peak noted.")
        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.invalid/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(json.loads(request.data)["messages"], messages)


if __name__ == "__main__":
    unittest.main()
