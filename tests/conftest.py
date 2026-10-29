import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".test-deps"))


def lua_to_py(value):
    if hasattr(value, "items"):
        data = dict(value.items())
        if data and all(isinstance(k, int) and 1 <= k <= len(data) for k in data):
            return [lua_to_py(data[k]) for k in range(1, len(data) + 1)]
        return {k: lua_to_py(v) for k, v in data.items()}
    return value


def to_lua(runtime, value):
    if isinstance(value, dict):
        return runtime.table_from({k: to_lua(runtime, v) for k, v in value.items()})
    if isinstance(value, list):
        return runtime.table_from([to_lua(runtime, v) for v in value])
    return value
