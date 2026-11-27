"""Reporter interface and registry.

A reporter turns a classifier.Report into a string (the CLI decides where
that string goes: stdout, a file, etc). Same registration pattern as
checkers and adapters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from debunk.classifier import Report


class Reporter(ABC):
    """Base class for one output format. Set `name` and implement `render`."""

    name: str = ""

    @abstractmethod
    def render(self, report: Report, quiet: bool = False) -> str:
        """Render `report` as a string. `quiet` asks for a shorter output."""


class ReporterRegistry:
    def __init__(self) -> None:
        self._items: dict[str, Reporter] = {}

    def register(self, cls: type[Reporter]) -> type[Reporter]:
        name = cls.name
        if not name:
            raise ValueError(f"{cls.__name__} must set a non-empty name")
        if name in self._items:
            raise ValueError(f"a reporter named {name!r} is already registered")
        self._items[name] = cls()
        return cls

    def get(self, name: str) -> Reporter | None:
        return self._items.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))


registry = ReporterRegistry()
register = registry.register  # use as @register on a Reporter subclass
