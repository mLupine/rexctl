import pytest

from rexctl import connection, stream
from rexctl.errors import ApiError, UnreachableError
from rexctl.stream import DataRejectedError, DataStream, TerminalFeed, Welcome


class FakeWs:
    def close(self) -> None:
        pass


def make_stream(monkeypatch, outcomes: list) -> DataStream:
    monkeypatch.setattr(stream.time, "sleep", lambda _s: None)
    welcome = Welcome(token=b"t" * 16, keep_ms=60000, nonce=1)
    data_stream = DataStream(url="https://x", ws=FakeWs(), welcome=welcome)

    def resume_once() -> FakeWs:
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(data_stream, "resume_once", resume_once)
    return data_stream


def test_resume_retries_while_server_still_holds_the_old_socket(monkeypatch):
    fresh = FakeWs()
    data_stream = make_stream(
        monkeypatch, [DataRejectedError("busy", reason=3), DataRejectedError("dup", reason=2), fresh]
    )
    data_stream.resume()
    assert data_stream.ws is fresh


def test_resume_gives_up_on_final_rejections(monkeypatch):
    data_stream = make_stream(monkeypatch, [DataRejectedError("bad", reason=5), FakeWs()])
    with pytest.raises(DataRejectedError):
        data_stream.resume()


def test_resume_stops_after_the_attempt_budget(monkeypatch):
    failures = [UnreachableError("down") for _ in range(connection.RECONNECT_ATTEMPTS)]
    data_stream = make_stream(monkeypatch, failures)
    with pytest.raises(UnreachableError):
        data_stream.resume()


def feed_with(reopen) -> TerminalFeed:
    welcome = Welcome(token=b"t" * 16, keep_ms=60000, nonce=1)
    return TerminalFeed(None, DataStream(url="https://x", ws=FakeWs(), welcome=welcome), reopen=reopen)


def test_feed_reopens_with_a_fresh_ticket_when_resume_is_rejected():
    welcome = Welcome(token=b"u" * 16, keep_ms=60000, nonce=2)
    fresh = DataStream(url="https://x", ws=FakeWs(), welcome=welcome)
    feed = feed_with(lambda: fresh)
    items = feed.reopen_after(DataRejectedError("gone", reason=3))
    assert [i["kind"] for i in items] == ["gap"] and feed.stream is fresh and not feed.ended
    assert feed.decoder.marker == b"\x1b_rex1;2;"


def test_feed_ends_when_the_block_is_gone_for_good():
    def reopen():
        raise ApiError("block closed")

    feed = feed_with(reopen)
    items = feed.reopen_after(DataRejectedError("gone", reason=3))
    assert items == [feed.ended] and feed.ended["reason"] == "stream_lost"


def test_feed_reopen_budget_is_bounded():
    feed = feed_with(lambda: feed.stream)
    for _ in range(connection.RECONNECT_ATTEMPTS):
        assert feed.reopen_after(DataRejectedError("gone", reason=3))[0]["kind"] == "gap"
    assert feed.reopen_after(DataRejectedError("gone", reason=3))[0]["kind"] == "end"
