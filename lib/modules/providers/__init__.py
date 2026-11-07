# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Reviewed lock-update providers.

The registry is intentionally static.  Catalog or CLI input is never treated as
an import path and there is no discovery or floating-provider fallback.
"""

from collections.abc import Callable

from lib.modules.locks import ArtifactLockFile
from lib.modules.providers.fdroid import update_fdroid_lock


LockUpdateProvider = Callable[..., ArtifactLockFile]

LOCK_UPDATE_PROVIDERS: dict[str, LockUpdateProvider] = {
    'fdroid-privileged-extension': update_fdroid_lock,
}


def get_lock_update_provider(module_id: str) -> LockUpdateProvider | None:
    """Return one reviewed provider without importing from user input."""

    return LOCK_UPDATE_PROVIDERS.get(module_id)


__all__ = ('get_lock_update_provider', 'update_fdroid_lock')
