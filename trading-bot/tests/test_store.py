import pytest

from bot.models import Candidate, Leg, Position
from bot.risk import RiskState
from bot.store import Store


def test_risk_state_round_trips():
    st = Store(":memory:")
    assert st.load_risk_state() is None
    s = RiskState(120.5, "2026-11-14", 110.0, True, 2, 7, "2026-11-14")
    st.save_risk_state(s)
    assert st.load_risk_state() == s
    s2 = RiskState(130.0, "2026-11-15", 125.0, False, 0, 0, None)
    st.save_risk_state(s2)
    assert st.load_risk_state() == s2


def test_position_with_two_legs_round_trips():
    st = Store(":memory:")
    p = Position(
        "SOL-USD", 0.1, 100.0, 90.0, 120.0, 5.0, 1000,
        legs=[Leg("b1", 0.05, "bracket", 90.0), Leg("s1", 0.05, "stop", 90.0)],
        half_taken=False, highest_close=101.0,
    )
    st.save_position(p)
    assert st.positions() == [p]
    p.half_taken = True
    p.legs = [Leg("s1", 0.05, "stop", 100.0)]
    st.save_position(p)  # upsert by product_id
    assert st.positions() == [p]
    st.delete_position("SOL-USD")
    assert st.positions() == []


def test_journal_rows_by_kind():
    st = Store(":memory:")
    st.journal("order", "SOL-USD", {"order_id": "o1"}, 100)
    rid = st.journal("fill", "SOL-USD", {"price": 99.5, "size": 0.1}, 200)
    rows = st.journal_rows("fill")
    assert len(rows) == 1
    assert rows[0]["id"] == rid and rows[0]["data"] == {"price": 99.5, "size": 0.1}
    assert rows[0]["product_id"] == "SOL-USD" and rows[0]["ts"] == 200
    assert len(st.journal_rows()) == 2
    assert st.journal_rows(since_ts=150) == rows


def test_api_spend_and_calls():
    st = Store(":memory:")
    st.journal("api_cost", None, {"cost_usd": 0.01}, 100)
    st.journal("api_cost", None, {"cost_usd": 0.02}, 200)
    st.journal("review", "SOL-USD", {"decision": "approve"}, 200)
    assert st.api_spend(0) == pytest.approx(0.03)
    assert st.api_spend(150) == pytest.approx(0.02)
    assert st.api_calls(0) == 2 and st.api_calls(201) == 0


def test_reopening_file_keeps_data(tmp_path):
    path = str(tmp_path / "bot.db")
    st = Store(path)
    st.save_risk_state(RiskState(100.0, "2026-11-14", 100.0, False, 0, 0, None))
    st.set_meta("regime", "risk_on")
    st.journal("alert", None, {"msg": "hi"}, 5)
    cand = Candidate("SOL-USD", 100.0, 90.0, 120.0, 5.0, 98.0, 1.2, 3600)
    sid = st.add_shadow(cand, "veto", 0.0, 10)
    st.save_position(Position("SOL-USD", 0.1, 100.0, 90.0, 120.0, 5.0, 1000))
    st.close()

    st2 = Store(path)
    assert st2.load_risk_state() == RiskState(100.0, "2026-11-14", 100.0, False, 0, 0, None)
    assert st2.get_meta("regime") == "risk_on" and st2.get_meta("missing") is None
    assert st2.journal_rows("alert")[0]["data"] == {"msg": "hi"}
    assert [p.product_id for p in st2.positions()] == ["SOL-USD"]
    shadows = st2.open_shadows()
    assert len(shadows) == 1 and shadows[0]["id"] == sid
    assert shadows[0]["entry"] == 100.0 and shadows[0]["decision"] == "veto"
    st2.close_shadow(sid, -1.0)
    assert st2.open_shadows() == []
