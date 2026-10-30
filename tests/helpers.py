import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "examples"))

from make_sample_events import FAILURE, SUCCESS, event_xml  # noqa: E402,F401
from winsecmon.config import load_config  # noqa: E402

SAMPLE_XML = ROOT / "examples" / "sample_events.xml"


def default_config():
    return load_config(None, env={}).config
