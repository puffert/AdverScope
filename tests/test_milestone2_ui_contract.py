from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_attack_surface_profiles_are_connected_to_the_vertical_workspace():
    app = (ROOT / "osai_security" / "static" / "app.js").read_text(encoding="utf-8")
    assert "targetSetupProfilePanel(project)" in app
    assert "wireTargetSetupProfile()" in app
    assert 'class="attack-surface-flow"' in app
    assert '"generic-json-chatbot"' in (ROOT / "osai_security" / "target_profiles.py").read_text(encoding="utf-8")
    assert "Profiles organize the existing Attack Surface" in app


def test_result_modes_accounting_filters_and_relationships_are_user_visible():
    app = (ROOT / "osai_security" / "static" / "app.js").read_text(encoding="utf-8")
    for phrase in (
        "Executive summary",
        "Pentester workspace",
        "Raw evidence",
        "Reviewed cases",
        "Model cases",
        "Unsupported",
        "Not tested",
        "Technique → cases → findings → reproductions",
        "traffic-search",
        "traffic-event-type",
        "traffic-case-id",
    ):
        assert phrase in app


def test_retest_workflow_requires_explicit_approval_and_explains_changed_conditions():
    app = (ROOT / "osai_security" / "static" / "app.js").read_text(encoding="utf-8")
    assert "Compare like a professional retest" in app
    assert "Changed test conditions" in app
    assert "Assessment methodology will change" in app
    assert "retest-methodology-preview" in app
    assert "pinned assessment methodology" in app
    assert "approve a new isolated retest run" in app
    assert "/run-comparison?" in app
    assert "/retest-report?" in app
    assert "/retest`" in app


def test_accessibility_and_progressive_disclosure_contracts_are_present():
    html = (ROOT / "osai_security" / "static" / "index.html").read_text(encoding="utf-8")
    css = (ROOT / "osai_security" / "static" / "app.css").read_text(encoding="utf-8")
    app = (ROOT / "osai_security" / "static" / "app.js").read_text(encoding="utf-8")
    assert "Skip to assessment workspace" in html
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert ".advanced-only" in css
    assert "aria-current" in app
    assert "aria-busy" in app
    assert "first-assessment-tutorial" in app
