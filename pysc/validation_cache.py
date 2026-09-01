"""Content-hash validation cache for Tenable check_audit runs.

A .audit file whose exact bytes already passed check_audit does not need
Docker again: identical content validates identically. The cache maps
sha256(content) -> pass timestamp and persists across runs, so re-downloads
of unchanged benchmarks and re-normalized identical outputs skip the
tenable/audit-utils container entirely. Any byte change misses the cache and
validates for real; failures are never cached.
"""

import hashlib
import json
import time
from pathlib import Path

CACHE_NAME = "validation_cache.json"


class ValidationCache:
    def __init__(self, path):
        self.path = Path(path)
        self.hits = 0
        self.misses = 0
        self._data = {}
        if self.path.is_file():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    @staticmethod
    def _digest(audit_path):
        sha = hashlib.sha256()
        with open(audit_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                sha.update(chunk)
        return sha.hexdigest()

    def wrap(self, module):
        """Patch module._run_check_audit_in_docker with the caching layer."""
        real = module._run_check_audit_in_docker
        if getattr(real, "_pysc_cached", False):
            return

        def cached_check(audit_path):
            try:
                digest = self._digest(audit_path)
            except OSError:
                return real(audit_path)
            if digest in self._data:
                self.hits += 1
                return 0, "cached: identical content previously passed check_audit"
            code, output = real(audit_path)
            self.misses += 1
            if code == 0:
                self._data[digest] = time.strftime("%Y-%m-%d %H:%M:%S")
                self.save()
            return code, output

        cached_check._pysc_cached = True
        module._run_check_audit_in_docker = cached_check

    def save(self):
        try:
            self.path.write_text(json.dumps(self._data, indent=0), encoding="utf-8")
        except OSError:
            pass

    def clear(self):
        self._data = {}
        self.path.unlink(missing_ok=True)


def enable(cfg, modules, revalidate=False):
    cache = ValidationCache(cfg.root / CACHE_NAME)
    if revalidate:
        cache.clear()
    for module in modules:
        cache.wrap(module)
    return cache
