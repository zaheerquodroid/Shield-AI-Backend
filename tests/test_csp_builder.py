"""Tests for CSP builder utilities."""

from __future__ import annotations

from proxy.middleware.csp_builder import build_csp, merge_csp, parse_csp


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
