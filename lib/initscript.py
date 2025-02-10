# SPDX-FileCopyrightText: 2024-2025 Andrew Gunnerson
# SPDX-License-Identifier: GPL-3.0-only

import dataclasses
import re
from typing import assert_never, override

from lib.filesystem import Contexts, ExtFs


@dataclasses.dataclass
class InitScript:
    name: str
    command: list[str]
    class_: str | None = None
    user: str | None = None
    group: str | None = None
    seclabel: str | None = None
    capabilities: list[str] = dataclasses.field(default_factory=list)
    env: dict[str, str] = dataclasses.field(default_factory=dict)
    condition: str | None = None
    blocking: bool = False

    @staticmethod
    def _escape(token: str) -> str:
        def replacement(match: re.Match[str]) -> str:
            value = match.group(1)

            if value == '\n':
                return r'\n'
            elif value == '\r':
                return r'\r'
            elif value == '\t':
                return r'\t'
            elif value == '\\':
                return r'\\'
            elif value == ' ':
                # We additionally escape spaces instead of adding double quotes.
                return r'\ '
            else:
                assert_never(value)

        return re.sub(r'(\n\r\t\\ )', replacement, token)

    @override
    def __str__(self) -> str:
        name_escaped = self._escape(self.name)
        command_escaped = ' '.join(self._escape(arg) for arg in self.command)

        lines = [
            f'service {name_escaped} {command_escaped}',
            '    oneshot',
        ]

        if self.class_:
            lines.append(f'    class {self._escape(self.class_)}')

        if self.user:
            lines.append(f'    user {self._escape(self.user)}')

        if self.group:
            lines.append(f'    group {self._escape(self.group)}')

        if self.seclabel:
            lines.append(f'    seclabel {self._escape(self.seclabel)}')

        if self.capabilities:
            caps_escaped = ' '.join(self._escape(c) for c in self.capabilities)
            lines.append(f'    capabilities {caps_escaped}')

        for k, v in self.env.items():
            lines.append(f'    setenv {self._escape(k)} {self._escape(v)}')

        if self.condition:
            lines.append('    disabled')
            lines.append('')
            # This is intentionally an unescaped raw string so that we don't
            # have to use an AST to represent boolean conditions.
            lines.append(f'on {self.condition}')
            if self.blocking:
                lines.append(f'    exec_start {name_escaped}')
            else:
                lines.append(f'    start {name_escaped}')

        lines.append('')

        return '\n'.join(lines)

    def add_to(self, system_fs: ExtFs):
        assert '/' not in self.name
        path = f'system/etc/init/{self.name}.rc'

        with system_fs.open(path, 'w') as f:
            f.write(str(self))
