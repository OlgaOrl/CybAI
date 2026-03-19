# Story #8: As a developer I want shared conventions defined
# so that all modules use consistent formats

import os


def test_demo_risks_is_importable():
    from cybai.demo_data import DEMO_RISKS  # noqa: F401


def test_demo_risks_is_not_empty():
    from cybai.demo_data import DEMO_RISKS

    assert len(DEMO_RISKS) > 0


def test_demo_risks_conform_to_schema():
    from cybai.demo_data import DEMO_RISKS
    from cybai.models import Risk

    for risk in DEMO_RISKS:
        assert isinstance(risk, Risk)


def test_demo_risks_have_valid_severity():
    from cybai.demo_data import DEMO_RISKS
    from cybai.models import SEVERITY_LEVELS

    for risk in DEMO_RISKS:
        assert risk.severity in SEVERITY_LEVELS


def test_demo_risks_content_is_in_estonian():
    from cybai.demo_data import DEMO_RISKS

    estonian_keywords = [
        "port",
        "haavatavus",
        "krüpteering",
        "ligipääs",
        "parool",
        "süsteem",
        "uuendus",
        "turvalisus",
        "kasutaja",
        "andmed",
        "võrk",
        "teenus",
    ]
    all_text = " ".join(f"{r.title} {r.description}".lower() for r in DEMO_RISKS)
    matches = [kw for kw in estonian_keywords if kw in all_text]
    assert len(matches) >= 2, "Demo andmed peavad olema eesti keeles"


def test_demo_mode_controlled_by_env_variable():
    from cybai.demo_data import is_demo_mode

    os.environ["DEMO_MODE"] = "true"
    assert is_demo_mode() is True

    os.environ["DEMO_MODE"] = "false"
    assert is_demo_mode() is False

    del os.environ["DEMO_MODE"]
    assert is_demo_mode() is False


def test_demo_risks_ids_are_unique():
    from cybai.demo_data import DEMO_RISKS

    ids = [r.id for r in DEMO_RISKS]
    assert len(ids) == len(set(ids))
