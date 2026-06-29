import os
import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import settings
from app.scanners.safe_target import ALLOW_PRIVATE_RANGES, ALLOW_LOOPBACK

print("CWD:", os.getcwd())
print("PQC_ALLOW_PRIVATE_RANGES in settings:", settings.PQC_ALLOW_PRIVATE_RANGES)
print("PQC_ALLOW_LOOPBACK in settings:", settings.PQC_ALLOW_LOOPBACK)
print("ALLOW_PRIVATE_RANGES in safe_target:", ALLOW_PRIVATE_RANGES)
print("ALLOW_LOOPBACK in safe_target:", ALLOW_LOOPBACK)
