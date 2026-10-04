from __future__ import annotations

from typing import Any

from backend.normalization.normalize import normalize_security_event


class BaseAdapter:
    platform: str = "generic"

    def __init__(self, source_name: str):
        self.source_name = source_name

    def ingest(self, raw_event: dict[str, Any]) -> dict[str, Any]:
        raw_event = {**raw_event, "source_platform": self.platform, "source": raw_event.get("source", self.source_name)}
        return normalize_security_event(raw_event)


class WindowsAdapter(BaseAdapter):
    platform = "windows"


class LinuxAdapter(BaseAdapter):
    platform = "linux"


class NetworkAdapter(BaseAdapter):
    platform = "network"


class CloudAdapter(BaseAdapter):
    platform = "cloud"


class WebApplicationAdapter(BaseAdapter):
    platform = "web"


class IoTAdapter(BaseAdapter):
    platform = "iot"
