"""Safe integrations with externally installed security tools.

The package intentionally exposes a small, stable surface.  Tool-specific raw
output stays behind the adapters and every process is launched by the same
bounded runner.
"""

from app.tools.amass import AmassAdapter, AmassRequest, AmassScopeError
from app.tools.base import ToolAdapter, ToolExecution, ToolHealth, ToolState
from app.tools.depscan import DepScanAdapter, DepScanMode, DepScanRequest
from app.tools.openscap import OpenScapAdapter, OpenScapRequest
from app.tools.osquery import DEFAULT_QUERY_REGISTRY, OsqueryAdapter
from app.tools.osv_scanner import OsvScannerAdapter, OsvScanRequest
from app.tools.runner import (
    CommandResult,
    ExecutableNotAllowedError,
    InvalidCommandError,
    SafeSubprocessRunner,
    ToolUnavailableError,
)

__all__ = [
    "DEFAULT_QUERY_REGISTRY",
    "AmassAdapter",
    "AmassRequest",
    "AmassScopeError",
    "CommandResult",
    "DepScanAdapter",
    "DepScanMode",
    "DepScanRequest",
    "ExecutableNotAllowedError",
    "InvalidCommandError",
    "OpenScapAdapter",
    "OpenScapRequest",
    "OsqueryAdapter",
    "OsvScanRequest",
    "OsvScannerAdapter",
    "SafeSubprocessRunner",
    "ToolAdapter",
    "ToolExecution",
    "ToolHealth",
    "ToolState",
    "ToolUnavailableError",
]
