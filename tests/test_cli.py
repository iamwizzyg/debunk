import pytest

from debunk import __version__
from debunk.cli import main


def test_version_flag_prints_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert f"debunk {__version__}" in capsys.readouterr().out


def test_no_args_prints_help_and_exits_zero(capsys):
    assert main([]) == 0
    assert "usage: debunk" in capsys.readouterr().out
