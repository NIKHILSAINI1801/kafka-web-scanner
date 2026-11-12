from datetime import UTC, datetime, timedelta, timezone

from kafka.util import clean_text, format_utc, sanitize_filename, truncate


def test_clean_text_strips_terminal_escape_sequences():
    assert clean_text("a\x1b[31mred\x1b[0mb") == "a[31mred[0mb"
    assert "\x1b" not in clean_text("\x1b]0;title\x07x")


def test_clean_text_removes_control_and_bidi_override_characters():
    assert clean_text("safe\u202etxt.exe\x00\x07") == "safetxt.exe"


def test_clean_text_newlines_are_flattened_unless_requested():
    assert clean_text("a\nb\tc\r\nd") == "a b c  d"
    assert clean_text("a\nb", keep_newlines=True) == "a\nb"


def test_clean_text_truncates_with_marker():
    out = clean_text("x" * 50, max_length=10)
    assert len(out) == 10
    assert out.endswith("...")


def test_truncate_leaves_short_text_alone():
    assert truncate("abc", 10) == "abc"


def test_sanitize_filename_blocks_path_traversal_and_separators():
    name = sanitize_filename("../../etc/passwd")
    assert "/" not in name and "\\" not in name and ".." not in name
    assert sanitize_filename("a\\b:c*d?e") == "a_b_c_d_e"


def test_sanitize_filename_never_returns_empty_and_caps_length():
    assert sanitize_filename("...") == "target"
    assert len(sanitize_filename("a" * 500, max_length=40)) <= 40


def test_format_utc_normalises_timezone():
    moment = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert format_utc(moment) == "2026-01-02T03:04:05Z"
    plus_two = datetime(2026, 1, 2, 5, 4, 5, tzinfo=timezone(timedelta(hours=2)))
    assert format_utc(plus_two) == "2026-01-02T03:04:05Z"
