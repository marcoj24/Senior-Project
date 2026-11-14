from bot.alerts import Alerts


def test_send_posts_body_with_title_header():
    got = []
    a = Alerts("http://x/alert", None, post=lambda url, body, headers: got.append((url, body, headers)))
    a.send("stop hit", "BTC-USD stopped at 90")
    assert got == [("http://x/alert", b"BTC-USD stopped at 90", {"Title": "stop hit"})]


def test_failing_post_never_raises():
    def boom(url, body, headers):
        raise OSError("down")

    a = Alerts("http://x/alert", "http://x/beat", post=boom)
    a.send("t", "b")
    a.heartbeat()
    assert a.sent == [("t", "b")] and a.heartbeats == 1


def test_no_urls_is_a_no_op():
    def boom(*args):
        raise AssertionError("must not post")

    a = Alerts(None, None, post=boom)
    a.send("t", "b")
    a.heartbeat()


def test_heartbeat_posts_to_its_url():
    got = []
    Alerts(None, "http://x/beat", post=lambda *a: got.append(a)).heartbeat()
    assert got == [("http://x/beat", b"", {})]
