from debunk.baseline import ProbeRequest
from debunk.csrf import find_tokens, needs_refresh, refresh_probe


def test_finds_input_and_meta_tokens():
    page = (
        '<meta name="csrf-token" content="meta1">'
        '<form><input type="hidden" name="authenticity_token" value="in1">'
        "<input name='nonce' value='n1'></form>"
    )
    assert find_tokens(page) == {
        "csrf-token": "meta1",
        "authenticity_token": "in1",
        "nonce": "n1",
    }


def test_ignores_ordinary_inputs_and_empty_values():
    page = '<input name="q" value="x"><input name="csrf" value="">'
    assert find_tokens(page) == {}


def test_unescapes_html_and_skips_unsafe_values():
    page = '<input name="csrf" value="a&amp;b"><input name="nonce" value="x\ny">'
    assert find_tokens(page) == {"csrf": "a&b"}


def test_first_token_wins():
    page = '<input name="csrf" value="one"><input name="csrf" value="two">'
    assert find_tokens(page) == {"csrf": "one"}


def test_uppercase_tags_and_names():
    assert find_tokens('<INPUT NAME="CSRF" VALUE="up">') == {"csrf": "up"}


def test_needs_refresh_for_query_param():
    assert needs_refresh(ProbeRequest("GET", "https://e.com/s?csrf_token=x"))


def test_needs_refresh_for_header():
    probe = ProbeRequest("GET", "https://e.com/s", {"X-CSRF-Token": "x"})
    assert needs_refresh(probe)


def test_no_refresh_for_plain_requests():
    probe = ProbeRequest("GET", "https://e.com/s?q=1&token=abc", {"Cookie": "a=b"})
    assert not needs_refresh(probe)


def test_refresh_swaps_query_and_header_and_keeps_the_rest():
    probe = ProbeRequest(
        "GET",
        "https://e.com/s?csrf_token=old&q=1",
        {"X-CSRF-Token": "old", "Cookie": "a=b"},
    )
    fresh = refresh_probe(probe, {"csrf_token": "new"})
    assert fresh.url == "https://e.com/s?csrf_token=new&q=1"
    assert fresh.headers == {"X-CSRF-Token": "new", "Cookie": "a=b"}
    assert probe.url.endswith("csrf_token=old&q=1")


def test_header_is_only_replaced_by_a_csrf_style_token():
    probe = ProbeRequest(
        "GET", "https://e.com/s?nonce=old", {"X-CSRF-Token": "old"}
    )
    fresh = refresh_probe(probe, {"nonce": "n"})
    assert fresh.url == "https://e.com/s?nonce=n"
    assert fresh.headers == {"X-CSRF-Token": "old"}


def test_refresh_leaves_request_alone_when_names_do_not_match():
    probe = ProbeRequest("GET", "https://e.com/s?csrf_token=old")
    assert refresh_probe(probe, {"other": "x"}) == probe
