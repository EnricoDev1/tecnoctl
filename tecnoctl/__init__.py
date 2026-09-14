"""Public API for tecnoctl."""

from .client import AlarmClient, ProtocolError

__all__ = ["AlarmClient", "ProtocolError"]
