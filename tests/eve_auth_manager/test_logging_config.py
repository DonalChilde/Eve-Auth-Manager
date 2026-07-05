"""Tests for application logging configuration."""

from pathlib import Path

import eve_auth_manager.logging_config as logging_config_module


def test_setup_logging_creates_directory_and_installs_dict_config(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Logging setup should create the directory and pass a full dictConfig."""
    captured: dict[str, object] = {}
    log_dir = tmp_path / "logs"

    def fake_dict_config(config: dict[str, object]) -> None:
        captured["config"] = config

    monkeypatch.setattr(
        logging_config_module.logging.config, "dictConfig", fake_dict_config
    )

    logging_config_module.setup_logging(log_dir)

    assert log_dir.is_dir()
    config = captured["config"]
    assert isinstance(config, dict)
    assert config["version"] == 1
    assert config["disable_existing_loggers"] is False
    assert config["handlers"]["file"]["filename"] == log_dir / "debug.log"
    assert (
        config["handlers"]["rot_file_info"]["filename"] == log_dir / "rotating_info.log"
    )
    assert (
        config["handlers"]["rot_file_warn"]["filename"] == log_dir / "rotating_warn.log"
    )
    assert config["loggers"][""]["handlers"] == [
        "rot_file_info",
        "rot_file_warn",
        "console",
    ]
