"""Alerts and heartbeat. Neither ever raises, both time out after 10 seconds, and nothing here adds
keys or account identifiers: bodies carry what the caller passes (product ids, prices, reasons)."""

import urllib.request
from typing import Callable

TIMEOUT_S = 10


def _http_post(url: str, body: bytes, headers: dict) -> None:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT_S):
        pass


class Alerts:
    def __init__(self, alert_url: str | None = None, heartbeat_url: str | None = None,
                 post: Callable[[str, bytes, dict], None] | None = None):
        self.alert_url = alert_url
        self.heartbeat_url = heartbeat_url
        self.post = post or _http_post
        self.sent: list[tuple[str, str]] = []
        self.heartbeats = 0

    def send(self, title: str, body: str) -> None:
        self.sent.append((title, body))
        if not self.alert_url:
            return
        try:
            header_title = title.encode("ascii", "replace").decode("ascii")
            self.post(self.alert_url, body.encode("utf-8"), {"Title": header_title})
        except Exception:
            pass

    def heartbeat(self) -> None:
        self.heartbeats += 1
        if not self.heartbeat_url:
            return
        try:
            self.post(self.heartbeat_url, b"", {})
        except Exception:
            pass
