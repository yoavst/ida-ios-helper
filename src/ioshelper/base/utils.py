import contextlib
import re
from collections.abc import Callable, Hashable, Iterable, Iterator
from functools import wraps
from typing import Generic, TypeVar, overload


class CounterMixin:
    cnt: int = 0

    def count(self, amount: int = 1):
        self.cnt += amount


def match(arr: list[str | re.Pattern], item: str) -> bool:
    """Match a string against a list of strings or regex patterns."""
    for pat in arr:
        if isinstance(pat, str):
            if item == pat:
                return True
        else:
            if pat.match(item):
                return True
    return False


T = TypeVar("T")


def match_dict(patterns: dict[str | re.Pattern, T], item: str) -> T | None:
    """match a string against a dictionary of strings or regex patterns, Returns the value if matched."""
    for pat, val in patterns.items():
        if isinstance(pat, str):
            if item == pat:
                return val
        else:
            if pat.match(item):
                return val
    return None


K = TypeVar("K")
V = TypeVar("V")


class CustomDict(Generic[K, V]):
    def __init__(self, hasher: Callable[[K], Hashable]):
        self._hasher = hasher
        self._storage: dict[Hashable, tuple[K, V]] = {}

    def __setitem__(self, key: K, value: V):
        self._storage[self._hasher(key)] = (key, value)

    def __getitem__(self, key: K) -> V:
        return self._storage[self._hasher(key)][1]

    def __delitem__(self, key: K):
        del self._storage[self._hasher(key)]

    def __contains__(self, key: K) -> bool:
        return self._hasher(key) in self._storage

    def __str__(self) -> str:
        return f"{{ {', '.join(f'{key}: {value}' for key, value in self._storage.values())} }}"

    @overload
    def get(self, key: K) -> V | None: ...

    @overload
    def get(self, key: K, default: V) -> V: ...

    @overload
    def get(self, key: K, default: V | None) -> V | None: ...

    def get(self, key: K, default: V | None = None):
        if key in self:
            return self[key]
        return default

    def setdefault(self, key: K, default: V) -> V:
        cur = self.get(key)
        if cur is not None:
            return cur

        self[key] = default
        return default

    def __len__(self) -> int:
        return len(self._storage)

    def keys(self) -> Iterator[K]:
        return (k for k, _ in self._storage.values())

    def values(self) -> Iterator[V]:
        return (v for _, v in self._storage.values())

    def items(self) -> Iterator[tuple[K, V]]:
        return iter(self._storage.values())

    def __iter__(self) -> Iterator[K]:
        return self.keys()

    def __bool__(self) -> bool:
        return bool(self._storage)


class CustomSet(Generic[V]):
    def __init__(self, hasher: Callable[[V], Hashable]):
        self._hasher = hasher
        self._storage: dict[Hashable, V] = {}

    def add(self, value: V):
        self._storage[self._hasher(value)] = value

    def add_all(self, items: Iterator[V] | Iterable[V]):
        for item in items:
            self.add(item)

    def remove(self, value: V):
        del self._storage[self._hasher(value)]

    def discard(self, value: V):
        with contextlib.suppress(KeyError):
            self.remove(value)

    def __contains__(self, value: V) -> bool:
        return self._hasher(value) in self._storage

    def __len__(self) -> int:
        return len(self._storage)

    def __iter__(self) -> Iterator[V]:
        return iter(self._storage.values())

    def __bool__(self) -> bool:
        return bool(self._storage)

    def update(self, other: "CustomSet[V]") -> None:
        self._storage.update(other._storage)

    def __or__(self, other: "CustomSet[V]") -> "CustomSet[V]":
        new_set = CustomSet(self._hasher)
        new_set |= self
        new_set |= other
        return new_set

    def __ior__(self, other: "CustomSet[V]") -> "CustomSet[V]":
        self.update(other)
        return self

    def intersection_update(self, other: "CustomSet[V]") -> None:
        if not other:
            self._storage.clear()
            return

        self._storage = {k: self._storage[k] for k in (self._storage.keys() & other._storage.keys())}

    def __iand__(self, other: "CustomSet[V]") -> "CustomSet[V]":
        self.intersection_update(other)
        return self


def cache_fast(func: Callable[[], T]) -> Callable[[], T]:
    """Decorator to cache the result of a function for faster access."""
    cached_value: T | None = None

    @wraps(func)
    def wrapper():
        nonlocal cached_value
        if cached_value is None:
            cached_value = func()
        return cached_value

    return wrapper
