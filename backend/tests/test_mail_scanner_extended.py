import socket
from unittest.mock import patch, MagicMock
from app.scanners.mail_scanner import _do_mail_connect, _recv_line


class TestRecvLine:
    def test_simple_line(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"220 ", b"mx.example.com ESMTP\r\n"]
        result = _recv_line(mock_sock, 5)
        assert "220" in result
        assert "mx.example.com" in result

    def test_empty_recv_breaks(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        result = _recv_line(mock_sock, 5)
        assert result == ""


class TestDoMailConnect:
    def test_port_465_smtps_success(self, tmp_path):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_ssock.recv.return_value = b"220 mx.example.com ESMTP\r\n"
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.getpeercert.return_value = b"der-bytes"

        with patch("socket.create_connection") as mock_conn, patch(
            "ssl.create_default_context"
        ) as mock_ctx, patch(
            "ssl.DER_cert_to_PEM_cert",
            return_value="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        ), patch(
            "app.scanners.mail_scanner.parse_certificate",
            return_value={"thumbprint": "a" * 64},
        ):
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            ctx = MagicMock()
            ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
            ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ctx.return_value = ctx

            result = _do_mail_connect("mx.example.com", 465, 5, verify_tls=True)
        assert result["success"] is True
        assert result["mode"] == "smtps"
        assert result["starttls_supported"] is False

    def test_port_25_starttls_success(self):
        mock_sock = MagicMock()
        mock_ssock = MagicMock()
        mock_sock.recv.side_effect = [
            b"220 mx.example.com ESMTP\r\n",
            b"250-SIZE\r\n250-STARTTLS\r\n250 OK\r\n",
            b"220 Ready to start TLS\r\n",
        ]
        mock_ssock.version.return_value = "TLSv1.2"
        mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
        mock_ssock.getpeercert.return_value = b"der-bytes"

        with patch("socket.create_connection") as mock_conn, patch(
            "ssl.create_default_context"
        ) as mock_ctx, patch(
            "ssl.DER_cert_to_PEM_cert",
            return_value="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        ), patch(
            "app.scanners.mail_scanner.parse_certificate",
            return_value={"thumbprint": "b" * 64},
        ):
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            ctx = MagicMock()
            ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
            ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ctx.return_value = ctx

            result = _do_mail_connect("mx.example.com", 25, 5)
        assert result["success"] is True
        assert result["starttls_supported"] is True
        assert result["tls_version"] == "TLSv1.2"

    def test_unexpected_banner(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"550 Blocked\r\n"

        with patch("socket.create_connection") as mock_conn, patch(
            "ssl.create_default_context"
        ):
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            result = _do_mail_connect("mx.example.com", 25, 5)
        assert result["success"] is True
        assert "Unexpected" in result.get("error_message", "")

    def test_no_starttls_support(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"220 mx.example.com ESMTP\r\n",
            b"250-SIZE\r\n250 OK\r\n",
        ]

        with patch("socket.create_connection") as mock_conn, patch(
            "ssl.create_default_context"
        ):
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            result = _do_mail_connect("mx.example.com", 587, 5)
        assert result["success"] is True
        assert result["starttls_supported"] is False

    def test_starttls_rejected(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"220 mx.example.com ESMTP\r\n",
            b"250-SIZE\r\n250-STARTTLS\r\n250 OK\r\n",
            b"454 TLS not available\r\n",
        ]

        with patch("socket.create_connection") as mock_conn, patch(
            "ssl.create_default_context"
        ):
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            result = _do_mail_connect("mx.example.com", 587, 5)
        assert result["success"] is True
        assert result["starttls_supported"] is True
        assert "STARTTLS rejected" in result.get("error_message", "")

    def test_connection_refused(self):
        with patch(
            "socket.create_connection", side_effect=ConnectionError("refused")
        ), patch("ssl.create_default_context"):
            result = _do_mail_connect("mx.example.com", 25, 5)
        assert result["success"] is False
        assert "refused" in result["error_message"]

    def test_socket_timeout(self):
        with patch(
            "socket.create_connection", side_effect=socket.timeout("timed out")
        ), patch("ssl.create_default_context"):
            result = _do_mail_connect("mx.example.com", 25, 5)
        assert result["success"] is False
        assert "timed out" in result["error_message"]
