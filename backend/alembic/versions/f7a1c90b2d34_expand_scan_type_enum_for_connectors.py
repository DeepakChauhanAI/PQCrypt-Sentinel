"""expand_scan_type_enum_for_connectors

Revision ID: f7a1c90b2d34
Revises: a1e2f3c4d5b6
Create Date: 2026-06-17 12:00:00.000000

Add the scan_type values used by the connector endpoints in
app/api/connectors.py (winrm, kubernetes, oracle_tde, sqlserver_tde,
pkcs11_hsm, kmip_kms, adcs_ldap, jwt_audit, windows_cert_store).

Without these, every connector-backed scan insert fails with an
IntegrityError against the scans.scan_type CHECK constraint.

The model uses native_enum=False, so on Postgres this is a VARCHAR
column with a CHECK constraint. This migration replaces that CHECK
constraint with one covering the full value set. On SQLite (tests) the
column/constraint is rebuilt from create_all, so this is a no-op.
"""

from alembic import op


revision = "f7a1c90b2d34"
down_revision = "a1e2f3c4d5b6"
branch_labels = None
depends_on = None


# Complete, current set of allowed scan_type values. Kept in sync with
# Scan.scan_type in app/models/models.py.
ALL_SCAN_TYPES = [
    "full",
    "tls_only",
    "ssh_only",
    "targeted",
    "ct_monitor",
    "ca_sync",
    "cloud_sync",
    "cmdb_sync",
    "passive",
    "winrm",
    "kubernetes",
    "oracle_tde",
    "sqlserver_tde",
    "pkcs11_hsm",
    "kmip_kms",
    "adcs_ldap",
    "jwt_audit",
    "windows_cert_store",
]

ORIGINAL_SCAN_TYPES = [
    "full",
    "tls_only",
    "ssh_only",
    "targeted",
    "ct_monitor",
    "ca_sync",
    "cloud_sync",
    "cmdb_sync",
    "passive",
]


def _values_sql(values):
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite (tests): the table is rebuilt by SQLAlchemy create_all at
        # app startup with the current model constraint, so nothing to do.
        return

    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(bind)

    # Drop every existing CHECK constraint that gates scan_type, whether it
    # is the named scan_type_check or a system-generated one.
    for ck in inspector.get_check_constraints("scans"):
        sqltext = (ck.get("sqltext") or "").lower()
        if "scan_type" in sqltext:
            op.drop_constraint(ck["name"], "scans", type_="check")

    op.create_check_constraint(
        "scan_type_check",
        "scans",
        f"scan_type IN ({_values_sql(ALL_SCAN_TYPES)})",
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(bind)
    for ck in inspector.get_check_constraints("scans"):
        sqltext = (ck.get("sqltext") or "").lower()
        if "scan_type" in sqltext:
            op.drop_constraint(ck["name"], "scans", type_="check")

    op.create_check_constraint(
        "scan_type_check",
        "scans",
        f"scan_type IN ({_values_sql(ORIGINAL_SCAN_TYPES)})",
    )
