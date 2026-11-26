import pytest

from debunk.baseline import (
    CONTROL_VALUE,
    NOPE_PATH,
    BaselineError,
    control_request,
    nonexistent_url,
    replay_request,
    swap_param,
)
from debunk.schema import Finding, Request


def finding(**kw):
    base = {"id": "f1", "vuln_class": "xss_reflected", "target": "https://e.com/s"}
    base.update(kw)
    return Finding(**base)


def test_swap_param_replaces_and_keeps_the_rest():
    url = "https://e.com/s?a=1&q=old&b=2#x"
    assert swap_param(url, "q", "NEW") == "https://e.com/s?a=1&q=NEW&b=2#x"


def test_swap_param_replaces_every_copy():
    assert swap_param("https://e.com/s?q=1&q=2", "q", "N") == "https://e.com/s?q=N&q=N"


def test_swap_param_adds_when_missing():
    assert swap_param("https://e.com/s", "q", "NEW") == "https://e.com/s?q=NEW"
    assert swap_param("https://e.com/s?a=1", "q", "N") == "https://e.com/s?a=1&q=N"


def test_swap_param_encodes_the_value():
    assert swap_param("https://e.com/s?q=1", "q", "a b&c") == (
        "https://e.com/s?q=a%20b%26c"
    )


def test_swap_param_matches_encoded_names_and_keeps_them():
    assert swap_param("https://e.com/s?q%5Fx=1", "q_x", "N") == (
        "https://e.com/s?q%5Fx=N"
    )


def test_swap_param_keeps_ipv6_host():
    assert swap_param("http://[::1]:8080/s?q=1", "q", "Z") == "http://[::1]:8080/s?q=Z"


def test_replay_uses_the_findings_own_request():
    req = Request("HEAD", "https://e.com/s?q=1", {"Cookie": "a=b"})
    probe = replay_request(finding(request=req))
    assert (probe.method, probe.url) == ("HEAD", "https://e.com/s?q=1")
    assert probe.headers == {"Cookie": "a=b"}


def test_replay_builds_from_parameter_and_payload_when_request_missing():
    probe = replay_request(finding(parameter="q", payload="<b>"))
    assert probe.method == "GET"
    assert probe.url == "https://e.com/s?q=%3Cb%3E"


def test_replay_falls_back_to_the_target():
    assert replay_request(finding()).url == "https://e.com/s"


def test_control_swaps_the_named_parameter_and_keeps_headers():
    req = Request("GET", "https://e.com/s?q=%3Cb%3E", {"Cookie": "a=b"})
    f = finding(parameter="q", payload="<b>", request=req)
    control = control_request(f)
    assert control.url == f"https://e.com/s?q={CONTROL_VALUE}"
    assert control.headers == {"Cookie": "a=b"}
    assert replay_request(f).url == "https://e.com/s?q=%3Cb%3E"


def test_control_works_without_a_request():
    control = control_request(finding(parameter="q", payload="<b>"))
    assert control.url == f"https://e.com/s?q={CONTROL_VALUE}"


def test_control_finds_an_encoded_payload_without_a_parameter():
    req = Request("GET", "https://e.com/s?x=%3Cb%3E")
    control = control_request(finding(payload="<b>", request=req))
    assert control.url == f"https://e.com/s?x={CONTROL_VALUE}"


def test_control_finds_a_raw_payload_in_the_path():
    req = Request("GET", "https://e.com/p/<b>/x")
    control = control_request(finding(payload="<b>", request=req))
    assert control.url == f"https://e.com/p/{CONTROL_VALUE}/x"


def test_control_accepts_a_custom_value():
    control = control_request(finding(parameter="q"), "OTHER")
    assert control.url.endswith("q=OTHER")


def test_control_raises_when_nothing_can_be_swapped():
    with pytest.raises(BaselineError, match="cannot build"):
        control_request(finding())
    with pytest.raises(BaselineError):
        control_request(finding(payload="zzz", request=Request("GET", "https://e.com/")))


def test_nonexistent_url_is_a_sibling_in_the_same_directory():
    assert nonexistent_url("https://e.com/files/.env?x=1") == (
        "https://e.com/files" + NOPE_PATH
    )
    assert nonexistent_url("https://e.com/.env") == "https://e.com" + NOPE_PATH
    assert nonexistent_url("http://[::1]:8080/a/b") == "http://[::1]:8080/a" + NOPE_PATH
