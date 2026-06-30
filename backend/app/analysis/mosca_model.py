import os
from datetime import datetime
from typing import Optional

# Default quantum timeline year (Y in Mosca's X+Y>Z inequality).
# Mosca's published estimate puts the "Z" (time at which a CRQC can break
# RSA-2048) around 2034. Some NIST estimates push this to 2035+; we
# default to 2034 to be on the safe (earlier) side. Override via
# ``MOSCA_HORIZON_YEAR`` or ``QUANTUM_TIMELINE_YEAR``.
DEFAULT_QUANTUM_HORIZON_YEAR = 2034


def calculate_hndl_exposure(
    data_longevity_years: int, quantum_timeline_year: Optional[int] = None
) -> str:
    """
    Calculate HNDL exposure based on Mosca's Theorem:
    data_longevity vs quantum_timeline vs migration window.

    Acceptance Criteria:
    - data_longevity=0, quantum=2035 -> "none"
    - data_longevity=50, quantum=2035 -> "high"
    """
    if data_longevity_years <= 0:
        return "none"

    if quantum_timeline_year is None:
        # Prefer the dedicated env var, fall back to QUANTUM_TIMELINE_YEAR
        # (the config setting), then to the safe-side default.
        quantum_timeline_year = int(
            os.getenv("MOSCA_HORIZON_YEAR")
            or os.getenv("QUANTUM_TIMELINE_YEAR")
            or DEFAULT_QUANTUM_HORIZON_YEAR
        )

    current_year = datetime.now().year
    migration_window = quantum_timeline_year - current_year

    if migration_window < 0:
        # We have already passed the quantum timeline, so any long-lived data is high risk
        return "high"

    if migration_window < data_longevity_years:
        return "high"
    elif migration_window < data_longevity_years + 10:
        return "medium"
    else:
        return "low"
