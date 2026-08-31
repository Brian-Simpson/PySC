"""Configuration loading for pysc.

Reads pysc.toml (found next to the package root or given explicitly), resolves
all paths against [paths].root, and bridges settings into the vendored legacy
engine, which reads PYSC_* environment variables at import time and derives
defaults from its own SCRIPT_DIR.
"""

import os
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:  # Python 3.9
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


DEFAULT_CONFIG_NAME = "pysc.toml"

# Env vars the legacy engine reads at import time (ALL_AUDITS.py lines 282-303),
# mapped to their [paths] keys in pysc.toml.
_LEGACY_ENV_MAP = {
    "PYSC_BASELINE_MSSRV_CSV": "baseline_mssrv_csv",
    "PYSC_MERGED_MSSRV_CSV": "merged_mssrv_csv",
    "PYSC_DESCRIPTION_MATCH_XLSX": "description_match_xlsx",
    "PYSC_PRODUCTION_AUDIT_ROOT": "production_inputs",
    "PYSC_PRODUCTION_NORMALIZED_ROOT": "normalized",
    "PYSC_PRODUCTION_GAP_ROOT": "gap_staging",
    "PYSC_PRODUCTION_GAP_OUTPUT_ROOT": "gap_output",
}


class ConfigError(RuntimeError):
    pass


class Config:
    def __init__(self, data, source_path):
        self.data = data
        self.source_path = Path(source_path)
        paths = data.get("paths", {})
        root = paths.get("root")
        self.root = Path(root) if root else self.source_path.parent

    def path(self, key, default=None):
        """Resolve a [paths] entry against root. Returns None if unset/empty."""
        value = self.data.get("paths", {}).get(key, default)
        if not value:
            return None
        p = Path(value)
        return p if p.is_absolute() else self.root / p

    def normalize_setting(self, key, default=None, platform=None):
        """A [normalize] setting, with per-platform override."""
        if platform:
            plat = self.data.get("platforms", {}).get(platform, {})
            if key in plat:
                return plat[key]
        return self.data.get("normalize", {}).get(key, default)

    def platform(self, code):
        from pysc.platforms import canonical_platform

        return self.data.get("platforms", {}).get(canonical_platform(code), {})

    def platforms(self):
        return dict(self.data.get("platforms", {}))

    def baseline_path(self, code):
        """Absolute path to a platform's production baseline, or None."""
        name = self.platform(code).get("baseline")
        if not name:
            return None
        p = Path(name)
        if p.is_absolute():
            return p
        return self.path("production_inputs") / p


def find_config(start=None):
    """Walk up from start (default: cwd) looking for pysc.toml."""
    current = Path(start or os.getcwd()).resolve()
    for candidate in [current] + list(current.parents):
        cfg = candidate / DEFAULT_CONFIG_NAME
        if cfg.is_file():
            return cfg
    # Fall back to the config shipped next to this package.
    packaged = Path(__file__).resolve().parent.parent / DEFAULT_CONFIG_NAME
    if packaged.is_file():
        return packaged
    raise ConfigError(
        f"{DEFAULT_CONFIG_NAME} not found from {current} upward or beside the pysc package"
    )


def load_config(path=None):
    if tomllib is None:
        raise ConfigError("tomli is required on Python 3.9: pip install tomli")
    cfg_path = Path(path) if path else find_config()
    with open(cfg_path, "rb") as fh:
        data = tomllib.load(fh)
    return Config(data, cfg_path)


def apply_legacy_env(cfg):
    """Set PYSC_* env vars from config BEFORE importing the legacy engine.

    The legacy module reads these at import time; anything not covered here is
    patched onto the module afterwards by load_legacy().
    """
    for env_name, path_key in _LEGACY_ENV_MAP.items():
        value = cfg.path(path_key)
        if value is not None:
            os.environ[env_name] = str(value)


def load_legacy(cfg):
    """Import the vendored legacy engine configured for cfg.root.

    Sets env vars first (import-time reads), then patches module-level
    constants that the engine derives from its own file location: SCRIPT_DIR
    and AUDIT_INPUTS_ROOT are read at call time by main(), the --catalog path,
    and _run_merged_audit_generation(), so patching them after import is
    sufficient.
    """
    apply_legacy_env(cfg)
    import importlib

    legacy = importlib.import_module("pysc._legacy.all_audits")
    legacy.SCRIPT_DIR = str(cfg.root)
    vendor = cfg.path("vendor_inputs")
    if vendor is not None:
        legacy.AUDIT_INPUTS_ROOT = str(vendor)
    return legacy
