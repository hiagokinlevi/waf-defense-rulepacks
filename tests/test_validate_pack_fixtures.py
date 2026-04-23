import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "shared" / "validators" / "validate_pack.py"
FIXTURES = ROOT / "tests" / "fixtures"


def test_validate_pack_known_good_fixture_passes() -> None:
    good = FIXTURES / "pack_metadata_valid_minimal.json"
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(good)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_validate_pack_known_bad_fixture_fails() -> None:
    bad = FIXTURES / "pack_metadata_invalid_minimal.json"
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(bad)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, "Invalid fixture unexpectedly validated"
