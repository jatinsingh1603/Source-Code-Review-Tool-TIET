"""Opt-out switches for telemetry in dependencies and child processes (ADR-0005).

Owning epic: E01.

CodeKavach sends no telemetry of its own (ADR-0005). Some third-party tools it uses or launches
can, unless told not to through a documented environment variable. ``apply_opt_outs`` sets those
variables when the CLI starts (``codekavach.cli.app.main``); library users and the server (E32)
call it explicitly at start-up. Because environment variables are inherited, the switches also
reach engines launched as child processes.

Nothing runs at import time (E01-08 import purity), and the module imports only the standard
library so that it can run before everything else.
"""

import os
from collections.abc import Mapping, MutableMapping
from types import MappingProxyType
from typing import Final

# Each entry is a documented switch of the named tool. Later epics extend the table when they add
# a tool with such a switch, naming the tool and the epic (see ADR-0005, Implementation notes).
OPT_OUT_ENV: Final[Mapping[str, str]] = MappingProxyType(
    {
        "DO_NOT_TRACK": "1",  # tools that honour the cross-tool convention
        "HF_HUB_DISABLE_TELEMETRY": "1",  # Hugging Face Hub client (E08, E22)
        "SEMGREP_SEND_METRICS": "off",  # Semgrep as an external engine (E15)
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",  # .NET command-line tools for C# engines (E15)
        "SCARF_NO_ANALYTICS": "true",  # packages that embed Scarf install analytics
        "CHECKPOINT_DISABLE": "1",  # HashiCorp version and usage checks (IaC engines, E20)
    }
)


def apply_opt_outs(environ: MutableMapping[str, str] | None = None) -> dict[str, str]:
    """Set every opt-out variable that is not already set; return the ones this call set.

    A value the user set deliberately is kept. Nothing else in ``environ`` is read or removed.
    """
    target = os.environ if environ is None else environ
    applied: dict[str, str] = {}
    for name, value in OPT_OUT_ENV.items():
        if name not in target:
            target[name] = value
            applied[name] = value
    return applied
