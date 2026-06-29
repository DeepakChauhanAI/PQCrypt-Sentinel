import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from app.connectors.saml_connector import SAMLMetadataConnector
from app.models.models import Asset

xml_blob = """<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com">
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>
            MIIDBTCCAe2gAwIBAgIQY7nN...
          </X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>
"""

mock_cert_meta = {
    "thumbprint": "abcdef1234567890",
    "subject": "CN=example.com",
    "issuer": "CN=example.com",
    "sig_algorithm": "sha256WithRSAEncryption",
    "pub_key_algorithm": "RSA",
    "pub_key_size": 2048,
    "curve_name": None,
    "not_before": datetime(2026, 1, 1, tzinfo=timezone.utc),
    "not_after": datetime(2036, 1, 1, tzinfo=timezone.utc),
    "pqc_capable": False,
    "pqc_details": {
        "pqc_status": "vulnerable",
    }
}

mock_db = AsyncMock()
mock_db.execute.return_value.scalar_one_or_none.return_value = None

with patch("app.connectors.saml_connector.parse_certificate", return_value=mock_cert_meta):
    connector = SAMLMetadataConnector(xml_blob=xml_blob)
    res = asyncio.run(connector.sync(mock_db))

print("Result:", res)
