"""Download current vendor .audit benchmarks from Tenable's public downloads.

Source: the anonymous downloads API page 'download-all-compliance-audit-files',
whose audits.tar.gz carries every current Tenable-published audit file with an
API-published SHA-256 for integrity verification.

Flow (pysc download):
1. Fetch page metadata; locate the configured archive (default audits.tar.gz).
2. Download it (skipped if the cached copy already matches the SHA-256) and
   verify the digest.
3. Walk the tarball and keep members that are CIS_/DISA_/Tenable_ .audit files
   mapping to a platform declared in pysc.toml (same filename detection the
   rest of the toolkit uses).
4. Diff against audit_inputs: NEW (name not present), UPDATED (same name,
   different content), UNCHANGED. New/updated files land in a timestamped
   staging folder with a manifest for review.
5. --apply copies staged new/updated files into audit_inputs.

Everything uses the stdlib (urllib/tarfile/hashlib); Tenable's WAF requires a
non-default User-Agent.
"""

import csv
import hashlib
import json
import re
import tarfile
import time
import urllib.request
from pathlib import Path

from pysc.platforms import PlatformMatcher

API_BASE = "https://www.tenable.com/downloads/api/v2/pages"
DEFAULT_SLUG = "download-all-compliance-audit-files"
DEFAULT_ARCHIVE = "audits.tar.gz"
DEFAULT_USER_AGENT = "pysc-audit-toolkit/0.1"
VENDOR_PREFIX_RE = re.compile(r"^(CIS_|DISA_|Tenable_)", re.IGNORECASE)

# Tracked manifest of curated benchmark families. Folder contents come and go
# (clean-slate resets, pruning); this file is the durable memory of which
# families HTH curates, so 'pysc download' still stages the right benchmarks
# when audit_inputs starts empty.
MANIFEST_NAME = "curated_benchmarks.txt"


def load_manifest(root):
    path = Path(root) / MANIFEST_NAME
    if not path.is_file():
        return set()
    families = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            families.add(line)
    return families


def save_manifest(root, families):
    path = Path(root) / MANIFEST_NAME
    lines = [
        "# Curated benchmark families (version-agnostic). Maintained by",
        "# 'pysc download --apply'; hand-edit to adopt or retire a family.",
    ] + sorted(families)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def curated_families(cfg):
    """Union of families present in audit_inputs and the tracked manifest."""
    vendor_root = cfg.path("vendor_inputs")
    families = {family_key(p.name) for p in vendor_root.glob("*.audit")}
    families |= load_manifest(cfg.root)
    return families

# Version tokens inside benchmark filenames: v5.0.0 / v2.2.1 / v1r3 (DISA).
_VERSION_TOKEN_RE = re.compile(r"_v\d+(?:[\._]\d+)*(?:r\d+)?", re.IGNORECASE)


def family_key(filename):
    """Version-agnostic identity of a benchmark filename.

    CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_MS.audit and a future
    ..._v6.0.0_L1_MS.audit share a family; different products/levels do not.
    """
    name = Path(filename).name.lower()
    if name.endswith(".audit"):
        name = name[: -len(".audit")]
    return _VERSION_TOKEN_RE.sub("", name)


class DownloadError(RuntimeError):
    pass


def _request(url, user_agent):
    return urllib.request.Request(url, headers={"User-Agent": user_agent})


def fetch_metadata(slug=DEFAULT_SLUG, archive=DEFAULT_ARCHIVE, user_agent=DEFAULT_USER_AGENT):
    """Asset descriptor {file, size, sha256, file_url} for the archive."""
    url = f"{API_BASE}/{slug}"
    with urllib.request.urlopen(_request(url, user_agent), timeout=60) as resp:
        data = json.load(resp)
    assets = data.get("releases", {}).get("Configuration Auditing Files", [])
    for asset in assets:
        if asset.get("file") == archive:
            return asset
    raise DownloadError(
        f"Archive '{archive}' not found on downloads page '{slug}' "
        f"(available: {[a.get('file') for a in assets]})"
    )


def _sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_archive(asset, dest_dir, user_agent=DEFAULT_USER_AGENT, progress=print):
    """Download (or reuse a cached copy of) the archive; verify SHA-256."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / asset["file"]

    if target.is_file() and _sha256_of(target) == asset["sha256"]:
        progress(f"Cached archive is current: {target}")
        return target

    progress(f"Downloading {asset['file']} ({asset['size'] / 1e6:.1f} MB)...")
    with urllib.request.urlopen(_request(asset["file_url"], user_agent), timeout=300) as resp:
        with open(target, "wb") as fh:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                fh.write(chunk)

    actual = _sha256_of(target)
    if actual != asset["sha256"]:
        target.unlink(missing_ok=True)
        raise DownloadError(
            f"SHA-256 mismatch for {asset['file']}: expected {asset['sha256']}, got {actual}"
        )
    progress(f"Verified SHA-256: {actual}")
    return target


def relevant_platform(filename, matcher, vendor_only=True):
    """Platform code if the filename maps to a configured platform, else None."""
    name = Path(filename).name
    if vendor_only and not VENDOR_PREFIX_RE.match(name):
        return None
    return matcher.match(name)


def scan_archive(archive_path, matcher, vendor_only=True):
    """[(member, platform_code)] for relevant .audit members of the tarball."""
    matches = []
    with tarfile.open(archive_path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.lower().endswith(".audit"):
                continue
            code = relevant_platform(member.name, matcher, vendor_only)
            if code:
                matches.append((member.name, code))
    return matches


def stage(archive_path, matches, vendor_root, staging_dir, all_variants=False, progress=print, families=None):
    """Extract relevant members flat into staging; classify vs vendor_root.

    Returns rows: [{name, platform, status, staged_path}] with status:
    - UNCHANGED    same name, identical content (not staged)
    - UPDATED      same name, different content (staged)
    - NEW_VERSION  new name in a benchmark family already curated (staged)
    - OTHER        platform-relevant but not a curated family (manifest only,
                   staged when all_variants=True)
    Curated families default to the vendor folder's contents; pass `families`
    (folder + tracked manifest) so clean-slate resets keep working.
    Members are written by basename only (no archive paths are trusted).
    """
    vendor_root = Path(vendor_root)
    staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    if families is None:
        families = {family_key(p.name) for p in vendor_root.glob("*.audit")}
    curated = set(families)

    rows = []
    seen_names = set()
    with tarfile.open(archive_path, "r:gz") as tar:
        for member_name, code in matches:
            base = Path(member_name).name
            if base in seen_names:  # duplicate basename across archive dirs
                continue
            seen_names.add(base)

            existing = vendor_root / base
            if not existing.is_file() and family_key(base) not in curated:
                status = "OTHER"
                if not all_variants:
                    rows.append({"name": base, "platform": code, "status": status, "staged_path": ""})
                    continue
            elif existing.is_file():
                status = None  # decided below by content hash
            else:
                status = "NEW_VERSION"

            extracted = tar.extractfile(member_name)
            if extracted is None:
                continue
            content = extracted.read()

            if existing.is_file():
                if hashlib.sha256(existing.read_bytes()).hexdigest() == hashlib.sha256(content).hexdigest():
                    rows.append({"name": base, "platform": code, "status": "UNCHANGED", "staged_path": ""})
                    continue
                status = "UPDATED"

            staged_path = staging_dir / base
            staged_path.write_bytes(content)
            rows.append({"name": base, "platform": code, "status": status, "staged_path": str(staged_path)})

    manifest = staging_dir / "manifest.csv"
    with open(manifest, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["name", "platform", "status", "staged_path"])
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda r: (r["status"], r["platform"], r["name"])))
    progress(f"Manifest: {manifest}")
    return rows


def apply_staged(rows, vendor_root, progress=print):
    """Copy staged UPDATED/NEW_VERSION (and --all staged OTHER) files into
    the vendor inputs tree."""
    import shutil

    vendor_root = Path(vendor_root)
    applied = 0
    for row in rows:
        if row["staged_path"]:
            shutil.copy2(row["staged_path"], vendor_root / row["name"])
            applied += 1
            progress(f"[{row['status']}] {row['name']} -> {vendor_root}")
    return applied


def _post_apply_library_update(cfg, applied_rows, vendor_root, progress):
    """After applying downloads: report what each new benchmark adds vs the
    control library, then rebuild the library to accept the changes."""
    from pysc.library import LIBRARY_NAME, check_audit_file, load_library, run_build

    library_path = cfg.root / LIBRARY_NAME
    if library_path.is_file():
        controls = load_library(library_path)
        matcher = PlatformMatcher.from_config(cfg)
        for row in applied_rows:
            results = check_audit_file(
                controls, Path(vendor_root) / row["name"], matcher=matcher
            )
            counts = {}
            for r in results:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
            summary = " | ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
            progress(f"Library check [{row['status']}] {row['name']}: {summary}")
            for r in results:
                if r["status"] == "NEW":
                    progress(f"  NEW control: {r['key']} expected={r['expected']}")
    else:
        progress("No control library yet - building one now.")

    progress("Rebuilding control library...")
    run_build(cfg, progress=progress)


def covered_platforms(cfg):
    """Platforms whose declared production baseline exists on disk.

    Program rule: no .audit file is processed, parsed, or reported without a
    corresponding baseline in actual_audit_inputs.
    """
    covered = set()
    for code in cfg.platforms():
        baseline = cfg.baseline_path(code)
        if baseline is not None and baseline.is_file():
            covered.add(code)
    return covered


def run(cfg, apply=False, keep_archive=True, all_variants=False, update_library=True, progress=print):
    """Full download flow driven by pysc.toml. Returns the staged rows."""
    dl_cfg = cfg.data.get("downloads", {})
    slug = dl_cfg.get("page", DEFAULT_SLUG)
    archive = dl_cfg.get("archive", DEFAULT_ARCHIVE)
    user_agent = dl_cfg.get("user_agent", DEFAULT_USER_AGENT)

    cache_dir = cfg.root / dl_cfg.get("cache_dir", "Downloads_Cache")
    vendor_root = cfg.path("vendor_inputs")
    staging_dir = vendor_root / f"_incoming_{time.strftime('%y%m%d%H%M')}"

    asset = fetch_metadata(slug, archive, user_agent)
    archive_path = download_archive(asset, cache_dir, user_agent, progress)

    configured = PlatformMatcher.from_config(cfg)
    matches = scan_archive(archive_path, configured)

    covered = covered_platforms(cfg)
    uncovered = sorted({code for _name, code in matches if code not in covered})
    matches = [(name, code) for name, code in matches if code in covered]
    if uncovered:
        progress(
            "Skipping platforms without a production baseline: "
            + ", ".join(uncovered)
        )
    progress(f"Relevant .audit files in archive: {len(matches)}")

    families = curated_families(cfg)
    rows = stage(archive_path, matches, vendor_root, staging_dir, all_variants, progress, families)
    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    progress(
        f"UPDATED: {counts.get('UPDATED', 0)} | "
        f"NEW_VERSION: {counts.get('NEW_VERSION', 0)} | "
        f"UNCHANGED: {counts.get('UNCHANGED', 0)} | "
        f"OTHER (not curated): {counts.get('OTHER', 0)}"
    )

    staged = [r for r in rows if r["staged_path"]]
    if apply:
        applied = apply_staged(rows, vendor_root, progress)
        progress(f"Applied {applied} file(s) into {vendor_root}")
        # Persist the curated-family memory so clean-slate resets keep working.
        families |= {family_key(p.name) for p in vendor_root.glob("*.audit")}
        save_manifest(cfg.root, families)
        if applied and update_library:
            _post_apply_library_update(cfg, staged, vendor_root, progress)
    elif staged:
        progress(f"Review staged files in {staging_dir}, then re-run with --apply")
    else:
        progress("Vendor inputs are current with Tenable downloads.")

    if not keep_archive:
        archive_path.unlink(missing_ok=True)
    return rows
