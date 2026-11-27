"""Adapter interface and registry.

An adapter turns some input on disk (a generic findings file, a Strix run
directory, and so on) into a debunk LoadResult. Every adapter is read-only:
it only reads from `path` and never sends network requests itself.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from debunk.schema import LoadResult


class AdapterError(Exception):
    """The input at `path` could not be read as this adapter's format."""


class Adapter(ABC):
    """Base class for one input format. Set `name` and implement `load`."""

    name: str = ""

    @abstractmethod
    def load(self, path: str) -> LoadResult:
        """Read findings from `path` (a file or directory, format-specific)."""


class AdapterRegistry:
    def __init__(self) -> None:
        self._items: dict[str, Adapter] = {}

    def register(self, cls: type[Adapter]) -> type[Adapter]:
        name = cls.name
        if not name:
            raise ValueError(f"{cls.__name__} must set a non-empty name")
        if name in self._items:
            raise ValueError(f"an adapter named {name!r} is already registered")
        self._items[name] = cls()
        return cls

    def get(self, name: str) -> Adapter | None:
        return self._items.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))


registry = AdapterRegistry()
register = registry.register  # use as @register on an Adapter subclass
