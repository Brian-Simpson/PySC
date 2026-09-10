"""``tap`` — the command name for the HTH Tenable Audit Program CLI.

Thin alias package: all functionality lives in :mod:`pysc`. This exists so the
toolkit is invoked as ``python -m tap <command>`` (or the ``tap`` console
script) instead of ``python -m pysc``.
"""

from pysc.cli import main  # noqa: F401
