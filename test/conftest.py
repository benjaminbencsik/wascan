import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def sample_target():
    return "https://example.com"


@pytest.fixture
def sample_result():
    from wascan import ScanResult
    return ScanResult(target="https://example.com", started_at="2024-01-01T00:00:00")
