import importlib

try:
    importlib.import_module("aiosqlite")
except ModuleNotFoundError as e:
    msg = (
        "aiosqlite is not installed. If you want to use pqcow-server, use "
        "`pip install pqcow[server]`"
    )
    raise ModuleNotFoundError(msg) from e

from .server import Server

__all__ = ("Server",)
