"""promptbadger: detection-as-code for LLM prompt injection."""

__version__ = "0.2.0"

from .canary import make_canary  # noqa: E402
from .models import Detection, Rule, ScanResult  # noqa: E402
from .rules import RuleError, load_rules  # noqa: E402
from .scanner import Scanner, scan, scan_context, scan_output  # noqa: E402

__all__ = [
    "Detection", "Rule", "RuleError", "ScanResult", "Scanner",
    "load_rules", "make_canary", "scan", "scan_context", "scan_output", "__version__",
]
