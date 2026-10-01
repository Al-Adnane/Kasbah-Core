from __future__ import annotations

import importlib
from typing import Any, Dict, Type

from .base import KasbahAdapter
from .errors import AdapterNotFound, AdapterLoadError
from .registry import REGISTRY


def _import_symbol(path: str):
    """
    path format: 'module.submodule:SymbolName'
    """
    if ":" not in path:
        raise AdapterLoadError(f"invalid adapter path (missing ':'): {path}")
    mod_name, sym_name = path.split(":", 1)
    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        raise AdapterLoadError(f"failed import module {mod_name}: {e}") from e
    try:
        sym = getattr(mod, sym_name)
    except Exception as e:
        raise AdapterLoadError(f"failed getattr {sym_name} from {mod_name}: {e}") from e
    return sym


def get_adapter_ids():
    return sorted(REGISTRY.keys())


def load_adapter(adapter_id: str, **kwargs: Any) -> KasbahAdapter:
    """
    Instantiate adapter by id.
    kwargs passed to adapter constructor if it accepts them.
    """
    if adapter_id not in REGISTRY:
        raise AdapterNotFound(f"adapter not found: {adapter_id}")

    sym = _import_symbol(REGISTRY[adapter_id])

    try:
        inst = sym(**kwargs)  # type: ignore
    except TypeError:
        # adapter has no kwargs constructor
        try:
            inst = sym()  # type: ignore
        except Exception as e:
            raise AdapterLoadError(f"failed instantiate adapter {adapter_id}: {e}") from e
    except Exception as e:
        raise AdapterLoadError(f"failed instantiate adapter {adapter_id}: {e}") from e

    if not isinstance(inst, KasbahAdapter):
        raise AdapterLoadError(f"{adapter_id} is not a KasbahAdapter: got {type(inst)}")

    return inst


def adapter_spec(adapter_id: str) -> Dict[str, Any]:
    a = load_adapter(adapter_id)
    try:
        return a.describe()
    except Exception as e:
        raise AdapterLoadError(f"describe() failed for {adapter_id}: {e}") from e
