"""The --format generic adapter: debunk's own documented JSON schema.

All the actual parsing and validation lives in schema.py (step 5); this
adapter only connects that to the shared Adapter interface.
"""

from __future__ import annotations

from debunk.adapters.base import Adapter, register
from debunk.schema import LoadResult, load_file


@register
class GenericAdapter(Adapter):
    name = "generic"

    def load(self, path: str) -> LoadResult:
        return load_file(path)
