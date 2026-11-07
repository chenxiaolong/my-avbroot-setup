# SPDX-FileCopyrightText: 2026 PixeneOS
# SPDX-License-Identifier: GPL-3.0-only

"""Shared validation patterns for module metadata."""

import re


LICENSE_PATTERN = re.compile(
    r'^(?:LicenseRef-[A-Za-z0-9][A-Za-z0-9.-]*|'
    r'[A-Za-z0-9][A-Za-z0-9.+-]*)'
    r'(?:\s+(?:AND|OR)\s+(?:LicenseRef-[A-Za-z0-9][A-Za-z0-9.-]*|'
    r'[A-Za-z0-9][A-Za-z0-9.+-]*))*$'
)
