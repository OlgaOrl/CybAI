# Story #8: As a developer I want shared conventions defined
# so that all modules use consistent formats

import json
import logging


def test_get_logger_is_importable():
    from cybai.logging_utils import get_logger  # noqa: F401


def test_logger_returns_logger_instance():
    from cybai.logging_utils import get_logger

    logger = get_logger("test_module")
    assert isinstance(logger, logging.Logger)


def test_log_output_is_valid_json(capsys):
    from cybai.logging_utils import get_logger

    logger = get_logger("test_module")
    logger.info("Testimine")

    captured = capsys.readouterr()
    output = captured.err or captured.out
    parsed = json.loads(output.strip())
    assert isinstance(parsed, dict)


def test_log_contains_required_fields(capsys):
    from cybai.logging_utils import get_logger

    logger = get_logger("scanner")
    logger.info("Skaneerimine algas")

    captured = capsys.readouterr()
    output = captured.err or captured.out
    parsed = json.loads(output.strip())

    assert "trace_id" in parsed
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "module" in parsed
    assert "message" in parsed


def test_log_module_field_matches_logger_name(capsys):
    from cybai.logging_utils import get_logger

    logger = get_logger("analyzer")
    logger.warning("Hoiatus")

    captured = capsys.readouterr()
    output = captured.err or captured.out
    parsed = json.loads(output.strip())

    assert parsed["module"] == "analyzer"


def test_log_level_field_is_correct(capsys):
    from cybai.logging_utils import get_logger

    logger = get_logger("notifier")
    logger.error("Viga")

    captured = capsys.readouterr()
    output = captured.err or captured.out
    parsed = json.loads(output.strip())

    assert parsed["level"].upper() == "ERROR"


def test_log_trace_id_is_present_and_nonempty(capsys):
    from cybai.logging_utils import get_logger

    logger = get_logger("routes")
    logger.info("Päring saabus")

    captured = capsys.readouterr()
    output = captured.err or captured.out
    parsed = json.loads(output.strip())

    assert parsed["trace_id"]
    assert len(parsed["trace_id"]) > 0


def test_no_pii_fields_in_log(capsys):
    from cybai.logging_utils import get_logger

    logger = get_logger("auth")
    logger.info("Kasutaja toimingud logitud")

    captured = capsys.readouterr()
    output = captured.err or captured.out
    parsed = json.loads(output.strip())

    pii_fields = {"email", "password", "ssn", "isikukood", "telefon", "ip_address"}
    logged_keys = set(parsed.keys())
    assert logged_keys.isdisjoint(
        pii_fields
    ), f"PII väljad leitud logis: {logged_keys & pii_fields}"
