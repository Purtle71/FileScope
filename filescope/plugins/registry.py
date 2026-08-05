from __future__ import annotations

from .android import AndroidPlugin
from .archive import ArchivePlugin
from .image import ImagePlugin
from .office import OfficePlugin
from .pe import PEPlugin
from .sqlite_plugin import SQLitePlugin
from .structured import StructuredTextPlugin

PLUGINS = [
    AndroidPlugin(),
    PEPlugin(),
    OfficePlugin(),
    SQLitePlugin(),
    ImagePlugin(),
    ArchivePlugin(),
    StructuredTextPlugin(),
]
