"""Resource registry: one module per LibreNMS object type, imported the first time a plan names it.

Each module defines ``RESOURCE = <Resource subclass>()``. Tests install stand-ins with :func:`register`; an
installed resource wins over the module of the same name until :func:`unregister` removes it.
"""

from __future__ import annotations

import importlib
from typing import Dict

from .base import INVERSE_KINDS, Field, PartialWrite, Resource, StepError, settles_at

__all__ = [
    "INVERSE_KINDS",
    "RESOURCE_NAMES",
    "Field",
    "PartialWrite",
    "Resource",
    "StepError",
    "get_resource",
    "register",
    "settles_at",
    "unregister",
]

RESOURCE_NAMES = ("device", "location", "device_group", "service", "alert_rule", "port", "alert")

_overrides: Dict[str, Resource] = {}


def get_resource(name: str) -> Resource:
    """The resource called *name*; ``KeyError`` for a name that is neither registered nor in RESOURCE_NAMES."""
    if name in _overrides:
        return _overrides[name]
    if name not in RESOURCE_NAMES:
        raise KeyError(name)
    return importlib.import_module(f".{name}", __name__).RESOURCE


def register(resource: Resource) -> None:
    """Install *resource* under ``resource.name`` (test seam), replacing any earlier one."""
    _overrides[resource.name] = resource


def unregister(name: str) -> None:
    """Remove a resource installed with :func:`register`; the module of that name (if any) is used again."""
    _overrides.pop(name, None)
