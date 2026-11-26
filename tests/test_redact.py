from debunk.redact import REDACTED, redact_headers, redact_text, redact_url


def test_sensitive_headers_hidden_case_insensitively():
    out = redact_headers(
        {"Cookie": "a=b", "authorization": "Bearer abc", "Accept": "*/*"}
    )
    assert out == [
        ("Cookie", REDACTED),
        ("authorization", REDACTED),
        ("Accept", "*/*"),
    ]


def test_repeated_header_pairs_are_all_redacted():
    out = redact_headers([("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
    assert out == [("Set-Cookie", REDACTED), ("Set-Cookie", REDACTED)]


def test_location_header_has_url_secrets_hidden():
    out = redact_headers({"Location": "/x?token=abc&y=1"})
    assert out == [("Location", "/x?token=[REDACTED]&y=1")]


def test_url_password_and_query_secret_hidden():
    url = "https://u:pw@example.com/a?q=1&token=abc&Y=2"
    assert redact_url(url) == (
        "https://[REDACTED]@example.com/a?q=1&token=[REDACTED]&Y=2"
    )


def test_url_fragment_secret_hidden():
    url = "https://e.com/cb#access_token=abc&state=1"
    assert redact_url(url) == "https://e.com/cb#access_token=[REDACTED]&state=1"


def test_encoded_param_name_is_recognised():
    assert redact_url("https://e.com/?api%5Fkey=abc") == (
        "https://e.com/?api%5Fkey=[REDACTED]"
    )


def test_clean_urls_are_unchanged():
    for url in ("http://[::1]:8080/p?q=1", "https://e.com/a/b#section"):
        assert redact_url(url) == url


def test_text_header_line_and_bearer_and_assignment():
    assert redact_text("Authorization: Bearer abcdefgh12345") == (
        "Authorization: [REDACTED]"
    )
    assert redact_text("curl x Bearer abcdefghij") == "curl x Bearer [REDACTED]"
    assert redact_text("token=abc123 next") == "token=[REDACTED] next"


def test_text_cookie_line_in_a_raw_request():
    raw = "GET /\nCookie: a=b; c=d\nHost: x"
    assert redact_text(raw) == "GET /\nCookie: [REDACTED]\nHost: x"


def test_text_jwt_hidden():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"
    assert redact_text(f"here {jwt} end") == "here [REDACTED] end"


def test_plain_text_is_unchanged():
    assert redact_text("nothing secret here") == "nothing secret here"
