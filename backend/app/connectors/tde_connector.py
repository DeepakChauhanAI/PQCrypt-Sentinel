import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.connectors.base import BaseConnector
from app.connectors.vault_helper import get_vault_secret
from app.models.models import Asset

logger = logging.getLogger(__name__)


class OracleTDEConnector(BaseConnector):
    """
    Oracle TDE (Transparent Data Encryption) scanner.
    Queries V$ENCRYPTION_WALLET, V$ENCRYPTED_TABLESPACES, etc.
    """

    def __init__(
        self,
        credentials_ref: Any,
        host: str,
        port: int = 1521,
        service_name: str = "ORCL",
        use_wallet: bool = True,
    ):
        super().__init__(f"Oracle TDE ({host}:{port}/{service_name})")
        self.credentials_ref = credentials_ref
        self.host = host
        self.port = port
        self.service_name = service_name
        self.use_wallet = use_wallet

    async def _get_credentials(self) -> Dict[str, Any]:
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and (
            "username" in self.credentials_ref or "password" in self.credentials_ref
        ):
            return self.credentials_ref

        vault_path = ""
        version = None
        if isinstance(self.credentials_ref, dict):
            vault_path = self.credentials_ref.get("vault_path", "")
            version = self.credentials_ref.get("version")
        elif hasattr(self.credentials_ref, "vault_path"):
            vault_path = getattr(self.credentials_ref, "vault_path", "")
            version = getattr(self.credentials_ref, "version", None)
        return await get_vault_secret(vault_path, version)

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        try:
            import cx_Oracle
        except ImportError as exc:
            raise RuntimeError(
                "cx_Oracle is required for Oracle TDE connector"
            ) from exc

        creds = await self._get_credentials()
        username = creds.get("username")
        password = creds.get("password")
        wallet_location = creds.get("wallet_location")

        if not username or not password:
            raise RuntimeError(
                "Oracle TDE connector requires username/password from vault"
            )

        errors: List[str] = []

        try:
            dsn = cx_Oracle.makedsn(
                self.host, self.port, service_name=self.service_name
            )

            if self.use_wallet and wallet_location:
                connection = cx_Oracle.connect(
                    user=username,
                    password=password,
                    dsn=dsn,
                    config_dir=wallet_location,
                    wallet_location=wallet_location,
                )
            else:
                connection = cx_Oracle.connect(
                    user=username,
                    password=password,
                    dsn=dsn,
                )

            cursor = connection.cursor()

            # 1. Check encryption wallet status
            cursor.execute(
                """
                SELECT wrl_type, wrl_parameter, status, wallet_type
                FROM v$encryption_wallet
            """
            )
            wallet_info = cursor.fetchone()
            wallet_data = {}
            if wallet_info:
                wallet_data = {
                    "wrl_type": wallet_info[0],
                    "wrl_parameter": wallet_info[1],
                    "status": wallet_info[2],
                    "wallet_type": wallet_info[3],
                }

            # 2. Get encrypted tablespaces
            cursor.execute(
                """
                SELECT ts.name, ts.encryptedts, ts.encryptionalg
                FROM v$tablespace ts
                JOIN v$encrypted_tablespaces ets ON ts.ts# = ets.ts#
            """
            )
            encrypted_tablespaces = []
            for row in cursor.fetchall():
                encrypted_tablespaces.append(
                    {
                        "tablespace_name": row[0],
                        "encrypted": row[1] == "ENCRYPTED",
                        "encryption_algorithm": row[2],
                    }
                )

            # 3. Get master encryption key info
            cursor.execute(
                """
                SELECT key_id, key_version, tag, creation_time, activation_time
                FROM v$encryption_keys
                WHERE activated = 'YES'
            """
            )
            master_keys = []
            for row in cursor.fetchall():
                master_keys.append(
                    {
                        "key_id": row[0],
                        "key_version": row[1],
                        "tag": row[2],
                        "creation_time": str(row[3]) if row[3] else None,
                        "activation_time": str(row[4]) if row[4] else None,
                    }
                )

            # 4. Check for column encryption
            cursor.execute(
                """
                SELECT owner, table_name, column_name, encryption_alg, salt, integrity_alg
                FROM dba_encrypted_columns
            """
            )
            encrypted_columns = []
            for row in cursor.fetchall():
                encrypted_columns.append(
                    {
                        "owner": row[0],
                        "table_name": row[1],
                        "column_name": row[2],
                        "encryption_algorithm": row[3],
                        "salt": row[4],
                        "integrity_algorithm": row[5],
                    }
                )

            cursor.close()
            connection.close()

            # Create asset record
            asset_name = f"oracle-tde:{self.host}:{self.port}/{self.service_name}"
            stmt = select(Asset).where(
                Asset.name == asset_name, Asset.deleted_at.is_(None)
            )
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()

            metadata = {
                "provider": "oracle_tde",
                "host": self.host,
                "port": self.port,
                "service_name": self.service_name,
                "wallet": wallet_data,
                "encrypted_tablespaces": encrypted_tablespaces,
                "master_keys": master_keys,
                "encrypted_columns": encrypted_columns,
                "tde_enabled": wallet_data.get("status") == "OPEN",
            }

            if existing:
                existing.asset_type = "database"
                existing.asset_metadata = metadata
                return {
                    "status": "success",
                    "updated": 1,
                    "imported": 0,
                    "errors": errors,
                }
            else:
                asset = Asset(
                    name=asset_name,
                    asset_type="database",
                    ip_address=self.host,
                    port=self.port,
                    protocol="oracle",
                    environment="onprem",
                    discovery_source="oracle_tde",
                    asset_metadata=metadata,
                )
                session.add(asset)
                return {
                    "status": "success",
                    "imported": 1,
                    "updated": 0,
                    "errors": errors,
                }

        except Exception as exc:
            errors.append(f"Oracle TDE scan failed: {exc}")
            logger.exception("Oracle TDE sync failed")
            return {"status": "error", "imported": 0, "updated": 0, "errors": errors}


class SQLServerTDEConnector(BaseConnector):
    """
    SQL Server TDE scanner.
    Queries sys.dm_database_encryption_keys, sys.certificates, sys.dm_server_services.
    """

    def __init__(
        self,
        credentials_ref: Any,
        host: str,
        port: int = 1433,
        database: str = "master",
        domain: Optional[str] = None,
    ):
        super().__init__(f"SQL Server TDE ({host}:{port})")
        self.credentials_ref = credentials_ref
        self.host = host
        self.port = port
        self.database = database
        self.domain = domain

    async def _get_credentials(self) -> Dict[str, Any]:
        # Direct credentials dictionary fallback/override
        if isinstance(self.credentials_ref, dict) and (
            "username" in self.credentials_ref or "password" in self.credentials_ref
        ):
            return self.credentials_ref

        vault_path = ""
        version = None
        if isinstance(self.credentials_ref, dict):
            vault_path = self.credentials_ref.get("vault_path", "")
            version = self.credentials_ref.get("version")
        elif hasattr(self.credentials_ref, "vault_path"):
            vault_path = getattr(self.credentials_ref, "vault_path", "")
            version = getattr(self.credentials_ref, "version", None)
        return await get_vault_secret(vault_path, version)

    async def sync(self, session: AsyncSession, **kwargs: Any) -> Dict[str, Any]:
        try:
            import pyodbc
        except ImportError as exc:
            raise RuntimeError(
                "pyodbc is required for SQL Server TDE connector"
            ) from exc

        creds = await self._get_credentials()
        username = creds.get("username")
        password = creds.get("password")

        if not username or not password:
            raise RuntimeError(
                "SQL Server TDE connector requires username/password from vault"
            )

        errors: List[str] = []

        conn_str = (
            f"DRIVER={{ODBC Driver 17 for SQL Server}};"
            f"SERVER={self.host},{self.port};"
            f"DATABASE={self.database};"
            f"UID={username};PWD={password};"
            f"Encrypt=yes;TrustServerCertificate=yes;"
        )

        try:
            conn = pyodbc.connect(conn_str, timeout=30)
            cursor = conn.cursor()

            # 1. Get database encryption keys status
            cursor.execute(
                """
                SELECT
                    db_name(database_id) AS database_name,
                    encryption_state,
                    key_algorithm,
                    key_length,
                    encryptor_type,
                    encryptor_thumbprint,
                    percent_complete
                FROM sys.dm_database_encryption_keys
            """
            )
            tde_databases = []
            for row in cursor.fetchall():
                state_map = {
                    0: "No encryption",
                    1: "Unencrypted",
                    2: "Encryption in progress",
                    3: "Encrypted",
                    4: "Key change in progress",
                    5: "Decryption in progress",
                    6: "Protection change in progress",
                }
                tde_databases.append(
                    {
                        "database_name": row[0],
                        "encryption_state": state_map.get(
                            row[1], f"Unknown ({row[1]})"
                        ),
                        "encryption_state_code": row[1],
                        "key_algorithm": row[2],
                        "key_length": row[3],
                        "encryptor_type": row[4],
                        "encryptor_thumbprint": row[5].hex() if row[5] else None,
                        "percent_complete": row[6],
                    }
                )

            # 2. Get certificate info used for TDE
            cursor.execute(
                """
                SELECT name, thumbprint, subject, expiry_date, start_date,
                       issuer_name, pvt_key_encryption_type_desc
                FROM sys.certificates
                WHERE pvt_key_encryption_type_desc IS NOT NULL
            """
            )
            certificates = []
            for row in cursor.fetchall():
                certificates.append(
                    {
                        "name": row[0],
                        "thumbprint": row[1].hex() if row[1] else None,
                        "subject": row[2],
                        "expiry_date": str(row[3]) if row[3] else None,
                        "start_date": str(row[4]) if row[4] else None,
                        "issuer_name": row[5],
                        "key_encryption_type": row[6],
                    }
                )

            # 3. Get symmetric keys
            cursor.execute(
                """
                SELECT name, key_algorithm, key_length,
                       key_guid, create_date
                FROM sys.symmetric_keys
                WHERE key_algorithm IS NOT NULL
            """
            )
            symmetric_keys = []
            for row in cursor.fetchall():
                symmetric_keys.append(
                    {
                        "name": row[0],
                        "algorithm": row[1],
                        "key_length": row[2],
                        "key_guid": str(row[3]) if row[3] else None,
                        "create_date": str(row[4]) if row[4] else None,
                    }
                )

            # 4. Check Always Encrypted columns
            cursor.execute(
                """
                SELECT
                    OBJECT_SCHEMA_NAME(c.object_id) AS schema_name,
                    OBJECT_NAME(c.object_id) AS table_name,
                    c.name AS column_name,
                    c.encryption_type_desc,
                    c.encryption_algorithm_name,
                    cm.name AS cmk_name,
                    cm.key_store_provider_name
                FROM sys.columns c
                JOIN sys.column_encryption_keys cek
                    ON c.column_encryption_key_id = cek.column_encryption_key_id
                JOIN sys.column_master_keys cm
                    ON cek.column_master_key_id = cm.column_master_key_id
                WHERE c.encryption_type IS NOT NULL
            """
            )
            encrypted_columns = []
            for row in cursor.fetchall():
                encrypted_columns.append(
                    {
                        "schema": row[0],
                        "table": row[1],
                        "column": row[2],
                        "encryption_type": row[3],
                        "encryption_algorithm": row[4],
                        "cmk_name": row[5],
                        "key_store_provider": row[6],
                    }
                )

            cursor.close()
            conn.close()

            # Create asset record
            asset_name = f"sqlserver-tde:{self.host}:{self.port}"
            stmt = select(Asset).where(
                Asset.name == asset_name, Asset.deleted_at.is_(None)
            )
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()

            metadata = {
                "provider": "sqlserver_tde",
                "host": self.host,
                "port": self.port,
                "instance": self.database,
                "tde_databases": tde_databases,
                "certificates": certificates,
                "symmetric_keys": symmetric_keys,
                "encrypted_columns": encrypted_columns,
                "tde_enabled": any(
                    db["encryption_state_code"] == 3 for db in tde_databases
                ),
            }

            if existing:
                existing.asset_type = "database"
                existing.asset_metadata = metadata
                return {
                    "status": "success",
                    "updated": 1,
                    "imported": 0,
                    "errors": errors,
                }
            else:
                asset = Asset(
                    name=asset_name,
                    asset_type="database",
                    ip_address=self.host,
                    port=self.port,
                    protocol="sqlserver",
                    environment="onprem",
                    discovery_source="sqlserver_tde",
                    asset_metadata=metadata,
                )
                session.add(asset)
                return {
                    "status": "success",
                    "imported": 1,
                    "updated": 0,
                    "errors": errors,
                }

        except Exception as exc:
            errors.append(f"SQL Server TDE scan failed: {exc}")
            logger.exception("SQL Server TDE sync failed")
            return {"status": "error", "imported": 0, "updated": 0, "errors": errors}
