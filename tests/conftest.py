"""Configure homeca through the environment before app modules are imported (they read it at import)."""
import os
import sys
import tempfile
from pathlib import Path

d = tempfile.mkdtemp()
Path(d, "master.key").write_text("test-master-key-123456\n")
os.environ.update(
    HOMECA_DATA=d, HOMECA_MASTER_KEY_FILE=str(Path(d, "master.key")), HOMECA_PUBLIC_URL="http://ca.home.arpa:8080",
    HOMECA_ACME_CLIENTS="10.1.1.0/24", HOMECA_ACME_HOSTNAME="ca.home.arpa", HOMECA_ACME_DAYS="90",
)
sys.path.insert(0, str(Path(__file__).parent.parent))
