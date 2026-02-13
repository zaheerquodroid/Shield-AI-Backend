"""Tests for CSP builder utilities."""

from __future__ import annotations

from proxy.middleware.csp_builder import build_csp, merge_csp, parse_csp


# ── parse_csp ────────────────────────────────────────────────────────────


class TestParseCsp:
    def test_simple_policy(self):
        result = parse_csp("default-src 'self'; script-src 'self' https:")
        assert result == {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https:"],
        }

    def test_empty_string(self):
        assert parse_csp("") == {}

    def test_whitespace_only(self):
        assert parse_csp("   ") == {}

    def test_single_directive(self):
        result = parse_csp("default-src 'none'")
        assert result == {"default-src": ["'none'"]}

    def test_directive_no_values(self):
        result = parse_csp("upgrade-insecure-requests")
        assert result == {"upgrade-insecure-requests": []}

    def test_trailing_semicolons(self):
        result = parse_csp("default-src 'self';;; script-src 'self';")
        assert result == {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
        }

    def test_case_insensitive_directives(self):
        result = parse_csp("Default-Src 'self'")
        assert "default-src" in result


class TestParseCspWhitespace:
    """Edge cases with whitespace in CSP strings."""

    def test_multiple_spaces_between_tokens(self):
        result = parse_csp("script-src   'self'   https:")
        assert result["script-src"] == ["'self'", "https:"]

    def test_leading_whitespace(self):
        result = parse_csp("  default-src 'self'")
        assert result == {"default-src": ["'self'"]}

    def test_whitespace_around_semicolons(self):
        result = parse_csp("  default-src 'self' ;  script-src 'self'  ")
        assert result == {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
        }

    def test_tab_characters(self):
        result = parse_csp("default-src\t'self'")
        assert result["default-src"] == ["'self'"]


class TestParseCspSpecialValues:
    """CSP values with special characters."""

    def test_nonce_value(self):
        result = parse_csp("script-src 'nonce-abc123'")
        assert result["script-src"] == ["'nonce-abc123'"]

    def test_sha256_hash(self):
        result = parse_csp("script-src 'sha256-dGVzdA=='")
        assert result["script-src"] == ["'sha256-dGVzdA=='"]

    def test_wildcard(self):
        result = parse_csp("img-src *")
        assert result["img-src"] == ["*"]

    def test_data_scheme(self):
        result = parse_csp("img-src 'self' data:")
        assert result["img-src"] == ["'self'", "data:"]

    def test_url_with_port(self):
        result = parse_csp("connect-src https://api.example.com:8443")
        assert result["connect-src"] == ["https://api.example.com:8443"]

    def test_multiple_urls(self):
        result = parse_csp("script-src https://a.com https://b.com https://c.com")
        assert result["script-src"] == ["https://a.com", "https://b.com", "https://c.com"]

    def test_unsafe_inline_and_eval(self):
        result = parse_csp("script-src 'self' 'unsafe-inline' 'unsafe-eval'")
        assert "'unsafe-inline'" in result["script-src"]
        assert "'unsafe-eval'" in result["script-src"]


class TestParseCspRealWorld:
    """Parse real CSP strings from our presets."""

    def test_strict_preset_csp(self):
        csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"
        result = parse_csp(csp)
        assert len(result) == 10
        assert result["default-src"] == ["'self'"]
        assert result["frame-ancestors"] == ["'none'"]
        assert result["object-src"] == ["'none'"]

    def test_balanced_preset_csp(self):
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; object-src 'none'"
        result = parse_csp(csp)
        assert len(result) == 10
        assert result["script-src"] == ["'self'", "'unsafe-inline'"]
        assert result["img-src"] == ["'self'", "data:", "https:"]
        assert result["frame-ancestors"] == ["'self'"]

    def test_permissive_preset_csp(self):
        csp = "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src * data:; font-src * data:; connect-src *; frame-ancestors 'self' https:; form-action 'self' https:; base-uri 'self'; object-src 'none'"
        result = parse_csp(csp)
        assert result["connect-src"] == ["*"]
        assert result["img-src"] == ["*", "data:"]
        assert "'unsafe-eval'" in result["script-src"]


# ── merge_csp ────────────────────────────────────────────────────────────


class TestMergeCsp:
    def test_merge_adds_new_values(self):
        base = {"script-src": ["'self'"]}
        override = {"script-src": ["https://cdn.example.com"]}
        result = merge_csp(base, override)
        assert result["script-src"] == ["'self'", "https://cdn.example.com"]

    def test_merge_deduplicates(self):
        base = {"script-src": ["'self'", "https:"]}
        override = {"script-src": ["'self'", "https://cdn.example.com"]}
        result = merge_csp(base, override)
        assert result["script-src"] == ["'self'", "https:", "https://cdn.example.com"]

    def test_merge_new_directive(self):
        base = {"default-src": ["'self'"]}
        override = {"font-src": ["https://fonts.googleapis.com"]}
        result = merge_csp(base, override)
        assert result["default-src"] == ["'self'"]
        assert result["font-src"] == ["https://fonts.googleapis.com"]

    def test_merge_empty_override(self):
        base = {"default-src": ["'self'"]}
        result = merge_csp(base, {})
        assert result == {"default-src": ["'self'"]}

    def test_merge_empty_base(self):
        override = {"script-src": ["https:"]}
        result = merge_csp({}, override)
        assert result == {"script-src": ["https:"]}

    def test_merge_does_not_mutate_inputs(self):
        base = {"script-src": ["'self'"]}
        override = {"script-src": ["https:"]}
        merge_csp(base, override)
        assert base == {"script-src": ["'self'"]}
        assert override == {"script-src": ["https:"]}

    def test_merge_both_empty(self):
        result = merge_csp({}, {})
        assert result == {}

    def test_merge_multiple_directives(self):
        base = {"script-src": ["'self'"], "style-src": ["'self'"]}
        override = {"script-src": ["https:"], "img-src": ["data:"]}
        result = merge_csp(base, override)
        assert result["script-src"] == ["'self'", "https:"]
        assert result["style-src"] == ["'self'"]
        assert result["img-src"] == ["data:"]

    def test_merge_preserves_all_base_directives(self):
        """Override should not remove any base directives."""
        base = parse_csp("default-src 'self'; script-src 'self'; style-src 'self'")
        override = parse_csp("script-src https://cdn.example.com")
        result = merge_csp(base, override)
        assert "default-src" in result
        assert "script-src" in result
        assert "style-src" in result

    def test_merge_override_with_empty_values(self):
        base = {"script-src": ["'self'"]}
        override = {"upgrade-insecure-requests": []}
        result = merge_csp(base, override)
        assert result["script-src"] == ["'self'"]
        assert result["upgrade-insecure-requests"] == []


# ── build_csp ────────────────────────────────────────────────────────────


class TestBuildCsp:
    def test_build_simple(self):
        directives = {"default-src": ["'self'"], "script-src": ["'self'", "https:"]}
        result = build_csp(directives)
        assert "default-src 'self'" in result
        assert "script-src 'self' https:" in result
        assert "; " in result

    def test_build_empty(self):
        assert build_csp({}) == ""

    def test_build_directive_no_values(self):
        result = build_csp({"upgrade-insecure-requests": []})
        assert result == "upgrade-insecure-requests"

    def test_roundtrip(self):
        original = "default-src 'self'; script-src 'self' https:; img-src * data:"
        parsed = parse_csp(original)
        rebuilt = build_csp(parsed)
        reparsed = parse_csp(rebuilt)
        assert parsed == reparsed

    def test_build_single_directive(self):
        result = build_csp({"default-src": ["'none'"]})
        assert result == "default-src 'none'"

    def test_build_many_values(self):
        result = build_csp({"script-src": ["'self'", "'unsafe-inline'", "https://a.com", "https://b.com"]})
        assert result == "script-src 'self' 'unsafe-inline' https://a.com https://b.com"

    def test_roundtrip_strict_preset(self):
        """Full roundtrip with the strict preset CSP."""
        csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"
        parsed = parse_csp(csp)
        rebuilt = build_csp(parsed)
        reparsed = parse_csp(rebuilt)
        assert parsed == reparsed
