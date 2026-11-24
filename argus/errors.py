"""Typed errors so tool failures stay actionable and never leak secrets."""


class ArgusError(Exception):
    """Base class for expected Argus failures."""


class ValidationError(ArgusError):
    """Input did not pass validation."""


class StateError(ArgusError):
    """The assessment is not in a state that allows this action."""


class BarrelError(ArgusError):
    """The Barrel MCP server could not be reached or started."""


class BarrelToolError(ArgusError):
    """A Barrel tool returned isError. The message is already redacted."""


class ReplayError(ArgusError):
    """A replay request failed in transit (timeout, DNS, connection)."""
