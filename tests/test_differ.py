from debunk.differ import compare, same_page
from debunk.engine import Response


def resp(text="", status=200, headers=(), truncated=False):
    return Response(
        "https://e.com/", status, tuple(headers), text.encode(), text, truncated
    )


def test_identical_pages():
    d = compare(resp("<p>hi there</p>"), resp("<p>hi there</p>"))
    assert d.identical
    assert d.similarity == 1.0
    assert d.added == () and d.removed == ()


def test_empty_bodies_are_identical():
    d = compare(resp(""), resp(""))
    assert d.identical and d.similarity == 1.0


def test_reflected_probe_is_masked_in_every_encoding():
    control = resp("<p>hello dbnkctl7391</p>")
    replay = resp("<p>hello &lt;script&gt;</p>")
    d = compare(control, replay, "dbnkctl7391", "<script>")
    assert d.identical


def test_csrf_input_value_is_ignored():
    a = resp('<form><input type="hidden" name="csrf_token" value="aaa"></form>')
    b = resp('<form><input type="hidden" name="csrf_token" value="bbb"></form>')
    assert compare(a, b).identical


def test_csrf_meta_content_is_ignored():
    a = resp('<meta name="csrf-token" content="aaa">')
    b = resp('<meta name="csrf-token" content="bbb">')
    assert compare(a, b).identical


def test_other_input_values_still_count():
    a = resp('<input name="id" value="1">')
    b = resp('<input name="id" value="2">')
    d = compare(a, b)
    assert not d.body_same
    assert any('value="2"' in tok for tok in d.added)


def test_hex_ids_and_uuids_are_ignored():
    a = resp("id 0123456789abcdef0123456789abcdef")
    b = resp("id fedcba9876543210fedcba9876543210")
    assert compare(a, b).identical
    c = resp("req 550e8400-e29b-41d4-a716-446655440000")
    e = resp("req 123e4567-e89b-12d3-a456-426614174000")
    assert compare(c, e).identical


def test_partial_similarity_and_samples():
    d = compare(resp("a b c d"), resp("a b c e"))
    assert d.similarity == 0.6
    assert d.added == ("e",) and d.removed == ("d",)
    assert d.added_count == 1 and d.removed_count == 1
    assert not same_page(d)


def test_added_sample_is_capped_but_counted():
    d = compare(resp(""), resp(" ".join(f"w{i}" for i in range(10))))
    assert len(d.added) == 5
    assert d.added_count == 10
    assert d.similarity == 0.0


def test_samples_are_redacted():
    d = compare(resp("x"), resp("token=abc123 x"))
    assert d.added == ("token=[REDACTED]",)


def test_status_change():
    d = compare(resp("same"), resp("same", status=404))
    assert d.status_changed and not d.identical
    assert "status 200->404" in d.summary()
    assert not same_page(d)


def test_location_change_is_decided_on_raw_but_shown_redacted():
    a = resp(status=302, headers=(("Location", "/x?token=abc"),))
    b = resp(status=302, headers=(("Location", "/x?token=def"),))
    d = compare(a, b)
    assert d.location_changed
    assert d.replay_location == "/x?token=[REDACTED]"


def test_content_type_ignores_case_and_parameters():
    a = resp("x", headers=(("Content-Type", "text/html; charset=utf-8"),))
    b = resp("x", headers=(("content-type", "TEXT/HTML"),))
    d = compare(a, b)
    assert not d.type_changed
    assert d.control_type == "text/html"


def test_truncated_flag_is_carried():
    assert compare(resp("x"), resp("x", truncated=True)).truncated


def test_same_page_for_identical_responses():
    assert same_page(compare(resp("a b"), resp("a b")))
