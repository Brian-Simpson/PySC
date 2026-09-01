"""Offline tests for the Tenable downloads workflow (no network in the suite).

The archive scan/stage/diff logic runs against a synthetic tarball; metadata
parsing and SHA verification run against local fixtures.
"""

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from pysc.downloads import (
    DownloadError,
    apply_staged,
    family_key,
    relevant_platform,
    scan_archive,
    stage,
)
from pysc.platforms import PlatformMatcher

# Mirrors the pysc.toml filename_tokens declarations.
TOKENS = {
    "MSSRV": ["Windows_Server"],
    "MSWRK": ["Windows_11"],
    "SQL": ["SQL_Server"],
    "RHEL": ["Hat_Enterprise_Linux"],
    "VMware": ["VMware"],
    "Azure": ["Microsoft_Azure"],
    "AWS": ["Amazon_Web_Services"],
    "NetIOS": ["Cisco_IOS"],
    "NetNXOS": ["Cisco_NX"],
    "NetASA": ["_ASA_"],
    "NetPAFW": ["Palo_Alto"],
    "NetF5": ["_F5_"],
    "NetACI": ["Cisco_ACI"],
}
MATCHER = PlatformMatcher(TOKENS)


def _make_archive(tmp_path, members):
    archive = tmp_path / "audits.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, content in members.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return archive


def test_relevant_platform_mapping():
    assert relevant_platform("CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_MS.audit", MATCHER) == "MSSRV"
    assert relevant_platform("portal_audits/CIS_F5_Networks_Benchmark_v1.0.0_L1.audit", MATCHER) == "NetF5"
    assert relevant_platform("DISA_STIG_VMware_vSphere_6.7_ESXi_v1r3.audit", MATCHER) == "VMware"
    assert relevant_platform("CIS_Microsoft_SQL_Server_2022_v1.2.1_L1_Database_Engine.audit", MATCHER) == "SQL"
    assert relevant_platform("CIS_Cisco_NX-OS_v1.2.0_L1.audit", MATCHER) == "NetNXOS"
    assert relevant_platform("CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0_L1.audit", MATCHER) == "NetPAFW"
    assert relevant_platform("CIS_Red_Hat_Enterprise_Linux_10_v1.0.1_L1_Server.audit", MATCHER) == "RHEL"
    # Non-vendor prefix rejected by default; token fallback works without it.
    assert relevant_platform("HTH_MSSRV_BASELINE.audit", MATCHER) is None
    assert relevant_platform("HTH_MSSRV_BASELINE.audit", MATCHER, vendor_only=False) == "MSSRV"
    # Unmappable platform rejected.
    assert relevant_platform("CIS_IBM_AIX_7_v1.0.0_L1.audit", MATCHER) is None


def test_platform_alias():
    from pysc.platforms import canonical_platform

    assert canonical_platform("MSSQL") == "SQL"
    assert canonical_platform("mssql") == "SQL"
    assert canonical_platform("SQL") == "SQL"
    assert canonical_platform("MSSRV") == "MSSRV"


def test_family_key_version_agnostic():
    assert family_key("CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_MS.audit") == family_key(
        "CIS_Microsoft_Windows_Server_2022_v6.1.0_L1_MS.audit"
    )
    assert family_key("DISA_STIG_VMware_vSphere_6.7_ESXi_v1r3.audit") == family_key(
        "DISA_STIG_VMware_vSphere_6.7_ESXi_v2r1.audit"
    )
    # Different level or product = different family.
    assert family_key("CIS_F5_Networks_Benchmark_v1.0.0_L1.audit") != family_key(
        "CIS_F5_Networks_Benchmark_v1.0.0_L2.audit"
    )
    assert family_key("CIS_Microsoft_Windows_Server_2022_v5.0.0_L1_MS.audit") != family_key(
        "CIS_Microsoft_Windows_Server_2025_v5.0.0_L1_MS.audit"
    )


def test_scan_stage_diff_apply(tmp_path):
    vendor_root = tmp_path / "audit_inputs"
    vendor_root.mkdir()
    (vendor_root / "CIS_Cisco_NX-OS_v1.2.0_L1.audit").write_text("old content", encoding="utf-8")
    (vendor_root / "CIS_F5_Networks_Benchmark_v1.0.0_L1.audit").write_text("same", encoding="utf-8")
    (vendor_root / "CIS_Microsoft_Windows_Server_2025_v2.0.0_L1_MS.audit").write_text("v2", encoding="utf-8")

    archive = _make_archive(
        tmp_path,
        {
            # UPDATED: exists with different content
            "audits/CIS_Cisco_NX-OS_v1.2.0_L1.audit": "new content",
            # UNCHANGED: exists with identical content
            "audits/CIS_F5_Networks_Benchmark_v1.0.0_L1.audit": "same",
            # NEW_VERSION: curated family, newer version
            "audits/CIS_Microsoft_Windows_Server_2025_v3.0.0_L1_MS.audit": "brand new",
            # OTHER: platform-relevant but not a curated family (Server 2016)
            "audits/CIS_Microsoft_Windows_Server_2016_v3.0.0_L1_MS.audit": "not curated",
            # Irrelevant: unmappable platform
            "audits/CIS_IBM_AIX_7_v1.0.0_L1.audit": "irrelevant",
            # Irrelevant: not an .audit file
            "audits/readme.txt": "not an audit",
        },
    )

    matches = scan_archive(archive, MATCHER)
    assert len(matches) == 4  # AIX and readme excluded

    staging = tmp_path / "staging"
    rows = stage(archive, matches, vendor_root, staging, progress=lambda *_: None)
    by_status = {r["name"]: r["status"] for r in rows}
    assert by_status == {
        "CIS_Cisco_NX-OS_v1.2.0_L1.audit": "UPDATED",
        "CIS_F5_Networks_Benchmark_v1.0.0_L1.audit": "UNCHANGED",
        "CIS_Microsoft_Windows_Server_2025_v3.0.0_L1_MS.audit": "NEW_VERSION",
        "CIS_Microsoft_Windows_Server_2016_v3.0.0_L1_MS.audit": "OTHER",
    }
    assert (staging / "manifest.csv").is_file()
    # Only UPDATED + NEW_VERSION are staged by default.
    assert not (staging / "CIS_F5_Networks_Benchmark_v1.0.0_L1.audit").exists()
    assert not (staging / "CIS_Microsoft_Windows_Server_2016_v3.0.0_L1_MS.audit").exists()
    assert (staging / "CIS_Microsoft_Windows_Server_2025_v3.0.0_L1_MS.audit").is_file()

    applied = apply_staged(rows, vendor_root, progress=lambda *_: None)
    assert applied == 2
    assert (vendor_root / "CIS_Cisco_NX-OS_v1.2.0_L1.audit").read_text(encoding="utf-8") == "new content"
    assert (vendor_root / "CIS_Microsoft_Windows_Server_2025_v3.0.0_L1_MS.audit").is_file()

    # --all stages the OTHER row too.
    staging_all = tmp_path / "staging_all"
    rows_all = stage(archive, matches, vendor_root, staging_all, all_variants=True, progress=lambda *_: None)
    other = [r for r in rows_all if r["name"].startswith("CIS_Microsoft_Windows_Server_2016")]
    assert other and other[0]["status"] == "OTHER" and other[0]["staged_path"]


def test_clean_slate_manifest_keeps_families(tmp_path):
    """After a clean-slate reset (empty audit_inputs), the tracked manifest
    still identifies curated families so downloads stage correctly."""
    from pysc.downloads import load_manifest, save_manifest

    vendor_root = tmp_path / "audit_inputs"
    vendor_root.mkdir()  # deliberately EMPTY

    families = {family_key("CIS_Microsoft_Windows_Server_2025_v2.1.0_L1_MS.audit")}
    save_manifest(tmp_path, families)
    assert load_manifest(tmp_path) == families

    archive = _make_archive(
        tmp_path,
        {"audits/CIS_Microsoft_Windows_Server_2025_v3.0.0_L1_MS.audit": "new version"},
    )
    matches = scan_archive(archive, MATCHER)

    # Without the manifest: unknown family -> OTHER (not staged).
    rows = stage(archive, matches, vendor_root, tmp_path / "s1", progress=lambda *_: None)
    assert rows[0]["status"] == "OTHER"

    # With the manifest families: recognized -> NEW_VERSION (staged).
    rows = stage(
        archive, matches, vendor_root, tmp_path / "s2",
        progress=lambda *_: None, families=load_manifest(tmp_path),
    )
    assert rows[0]["status"] == "NEW_VERSION" and rows[0]["staged_path"]


def test_sha256_mismatch_raises(tmp_path, monkeypatch):
    from pysc import downloads

    bogus = tmp_path / "cache"
    asset = {
        "file": "audits.tar.gz",
        "size": 4,
        "sha256": "0" * 64,
        "file_url": "https://example.invalid/audits.tar.gz",
    }

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        downloads.urllib.request,
        "urlopen",
        lambda req, timeout=0: FakeResponse(b"data"),
    )
    with pytest.raises(DownloadError):
        downloads.download_archive(asset, bogus, progress=lambda *_: None)
    assert not (bogus / "audits.tar.gz").exists()
