import pytest

from bot.config import Config, load_config


def test_defaults_match_spec():
    c = Config()
    assert (c.mode, c.risk_per_trade, c.max_open_risk) == ("paper", 0.03, 0.08)
    assert (c.stop_min, c.stop_max, c.daily_loss_halt, c.kill_drawdown) == (0.05, 0.15, 0.06, 0.25)
    assert (c.cost_max_frac_of_stop, c.min_net_rr, c.target_r) == (0.20, 1.5, 2.0)
    assert c.tiers == [(100, 2), (1000, 3), (10000, 5), (float("inf"), 6)]


def test_yaml_overrides_and_rejects_unknown(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("risk_per_trade: 0.02\n")
    assert load_config(str(p)).risk_per_trade == 0.02
    p.write_text("risk_per_trad: 0.02\n")
    with pytest.raises(ValueError):
        load_config(str(p))


def test_yaml_tiers_become_tuples_and_allow_inf(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("tiers: [[100, 1], [.inf, 4]]\n")
    assert load_config(str(p)).tiers == [(100, 1), (float("inf"), 4)]


def test_builder_defaults():
    c = Config()
    assert c.always_include == ["BTC-USD", "ETH-USD", "SOL-USD"]
    assert (c.model_small, c.model_large) == ("claude-haiku-5-5", "claude-sonnet-5-5")
    assert (c.alert_url, c.heartbeat_url, c.db_path) == (None, None, "bot.db")
    assert c.fill_wait_cycles == 3
    assert Config().always_include is not c.always_include


def test_example_file_lists_every_setting_at_its_default():
    from dataclasses import fields
    from pathlib import Path
    import yaml
    path = Path(__file__).resolve().parent.parent / "config.example.yaml"
    assert set(yaml.safe_load(path.read_text())) == {f.name for f in fields(Config)}
    assert load_config(str(path)) == Config()
