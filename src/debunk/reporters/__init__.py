"""Output reporters. Each reporter module registers itself on import."""

from debunk.reporters import (
    json_report,  # noqa: F401
    sarif,  # noqa: F401
    table,  # noqa: F401
)
