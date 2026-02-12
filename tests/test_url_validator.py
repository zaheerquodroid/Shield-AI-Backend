"""Tests for SSRF origin URL validation."""

from __future__ import annotations

import pytest

from proxy.middleware.url_validator import validate_origin_url


class TestValidUrls:
    """URLs that should pass validation."""

    def test_public_http(self):
        assert validate_origin_url("http://example.com:3000") is None

    def test_public_https(self):
        assert validate_origin_url("https://app.example.com") is None

    def test_public_ip(self):
        assert validate_origin_url("http://203.0.113.1:8080") is None


class TestBlockedSchemes:
    """Non-http(s) schemes should be rejected."""

    def test_ftp(self):
        result = validate_origin_url("ftp://example.com/file")
        assert result is not None
        assert "scheme" in result.lower()

    def test_file(self):
        result = validate_origin_url("file:///etc/passwd")
        assert result is not None

    def test_gopher(self):
        result = validate_origin_url("gopher://evil.com")
        assert result is not None


class TestBlockedPrivateIPs:
    """Private/reserved IPs should be blocked."""

    def test_localhost_127(self):
        result = validate_origin_url("http://127.0.0.1:3000")
        assert result is not None
        assert "blocked" in result.lower()

    def test_10_network(self):
        result = validate_origin_url("http://10.0.0.1:3000")
        assert result is not None

    def test_172_16_network(self):
        result = validate_origin_url("http://172.16.0.1:3000")
        assert result is not None

    def test_192_168_network(self):
        result = validate_origin_url("http://192.168.1.1:3000")
        assert result is not None

    def test_aws_metadata(self):
        """AWS metadata IP (169.254.169.254) must be blocked."""
        result = validate_origin_url("http://169.254.169.254/latest/meta-data/")
        assert result is not None
        assert "blocked" in result.lower()

    def test_ipv6_loopback(self):
        result = validate_origin_url("http://[::1]:3000")
        assert result is not None

    def test_zero_ip(self):
        result = validate_origin_url("http://0.0.0.0:3000")
        assert result is not None


class TestEdgeCases:
    """Edge cases for URL validation."""

    def test_missing_hostname(self):
        result = validate_origin_url("http://")
        assert result is not None

    def test_empty_string(self):
        result = validate_origin_url("")
        assert result is not None

    def test_hostname_not_ip(self):
        """Regular hostnames should pass (DNS resolution may or may not work)."""
        result = validate_origin_url("http://my-app.internal:3000")
        # Not an IP literal, DNS resolution is best-effort — should pass
        assert result is None
