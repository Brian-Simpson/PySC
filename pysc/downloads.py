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


def stage(archive_path, matches, vendor_root, staging_dir, all_variants=False, progress=print):
    """Extract relevant members flat into staging; classify vs vendor_root.

    Returns rows: [{name, platform, status, staged_path}] with status:
    - UNCHANGED    same name, identical content (not staged)
    - UPDATED      same name, different content (staged)
    - NEW_VERSION  new name in a benchmark family already curated (staged)
    - OTHER        platform-relevant but not a curated family (manifest only,
                   staged when all_variants=True)
    Members are written by basename only (no archive paths are trusted).
    """
    vendor_root = Path(vendor_root)
    staging_dir = Path(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    curated_families = {
        family_key(p.name) for p in vendor_root.glob("*.audit")
    }

    rows = []
    seen_names = set()
    with tarfile.open(archive_path, "r:gz") as tar:
        for member_name, code in matches:
            base = Path(member_name).name
            if base in seen_names:  # duplicate basename across archive dirs
                continue
            seen_names.add(base)

            existing = vendor_root / base
            if not existing.is_file() and family_key(base) not in curated_families:
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


def run(cfg, apply=False, keep_archive=True, all_variants=False, progress=print):
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
    progress(f"Relevant .audit files in archive: {len(matches)}")

    rows = stage(archive_path, matches, vendor_root, staging_dir, all_variants, progress)
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
    elif staged:
        progress(f"Review staged files in {staging_dir}, then re-run with --apply")
    else:
        progress("Vendor inputs are current with Tenable downloads.")

    if not keep_archive:
        archive_path.unlink(missing_ok=True)
    return rows
