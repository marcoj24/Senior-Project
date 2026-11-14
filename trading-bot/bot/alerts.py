class Alerts:
    """Recording stub; Task 12 replaces the bodies and keeps this constructor and `sent`."""

    def __init__(self, alert_url=None, heartbeat_url=None, post=None):
        self.alert_url = alert_url
        self.heartbeat_url = heartbeat_url
        self.post = post
        self.sent: list[tuple[str, str]] = []
        self.heartbeats = 0

    def send(self, title: str, body: str) -> None:
        self.sent.append((title, body))

    def heartbeat(self) -> None:
        self.heartbeats += 1
