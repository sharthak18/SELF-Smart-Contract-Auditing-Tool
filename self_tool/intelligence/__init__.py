"""Metadata-only advisory intelligence updater.

The updater pulls defensive metadata from allowlisted HTTPS hosts
into a local snapshot directory. It does **not** execute any downloaded
content. Records feed the calibration corpus and review-queue; they
do not auto-install new detector rules.
"""

from .cache import Cache, Snapshot
from .fetcher import FetchError, fetch_https
from .manifest import Manifest, ManifestEntry, verify_manifest
from .validator import validate_record
from .install import InstallError, install_snapshot, rollback

__all__ = [
    "Cache",
    "FetchError",
    "InstallError",
    "Manifest",
    "ManifestEntry",
    "Snapshot",
    "fetch_https",
    "install_snapshot",
    "rollback",
    "validate_record",
    "verify_manifest",
]
