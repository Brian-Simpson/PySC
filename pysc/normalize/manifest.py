#!/usr/bin/env python3
"""
Manifest-based deduplication for CIS benchmark processing.
Tracks which CIS versions have been normalized to skip re-processing unchanged files.
"""

import json
import os
import hashlib
from pathlib import Path


def get_manifest_path(cfg):
    """Get the manifest file path for tracking processed CIS versions."""
    return cfg.path("normalized") / ".cis_manifest.json"


def load_manifest(cfg):
    """Load the manifest of processed CIS versions."""
    manifest_path = get_manifest_path(cfg)
    if manifest_path.exists():
        try:
            with open(manifest_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_manifest(cfg, manifest):
    """Save the manifest of processed CIS versions."""
    manifest_path = get_manifest_path(cfg)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)


def get_file_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(filepath, 'rb') as f:
        sha.update(f.read())
    return sha.hexdigest()


def should_skip_file(filepath, manifest):
    """Check if a file should be skipped based on manifest."""
    filename = os.path.basename(filepath)

    if filename not in manifest:
        return False

    current_hash = get_file_hash(filepath)
    saved_hash = manifest[filename].get('hash')

    return current_hash == saved_hash


def mark_file_processed(filepath, manifest):
    """Mark a file as processed in the manifest."""
    filename = os.path.basename(filepath)
    manifest[filename] = {
        'hash': get_file_hash(filepath),
        'processed': True
    }
