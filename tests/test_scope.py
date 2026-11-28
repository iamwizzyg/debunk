import pytest

from debunk.scope import ScopeError, load_scope, make_guard


def test_load_scope_skips_blank_and_comment_lines(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# comment\n\nexample.com\n  *.example.org  \n")
    assert load_scope(str(f)) == ("example.com", "*.example.org")


def test_load_scope_missing_file_raises():
    with pytest.raises(ScopeError, match="cannot read"):
        load_scope("/no/such/file.txt")


def test_load_scope_empty_file_raises(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# just a comment\n\n")
    with pytest.raises(ScopeError, match="no patterns"):
        load_scope(str(f))


def test_guard_matches_exact_host_case_insensitively():
    guard = make_guard(("Example.com",))
    assert guard("https://example.com/x")
    assert guard("HTTPS://EXAMPLE.COM/x")
    assert not guard("https://other.com/x")


def test_guard_wildcard_matches_subdomains_not_apex():
    guard = make_guard(("*.example.com",))
    assert guard("https://api.example.com/x")
    assert not guard("https://example.com/x")


def test_guard_with_no_patterns_matches_nothing():
    assert not make_guard(())("https://example.com/x")


def test_guard_handles_url_with_no_host():
    guard = make_guard(("example.com",))
    assert not guard("not a url")
