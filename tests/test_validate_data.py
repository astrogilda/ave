import json

import pytest

from scripts import validate_crosswalks, validate_records


def test_record_validator_rejects_invalid_date_time_format():
    schema = json.loads(validate_records.SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = validate_records.build_validator(schema)
    record = {
        "ave_id": "AVE-2026-99999",
        "schema_version": "1.1.0",
        "status": "draft",
        "title": "Invalid date-time fixture",
        "description": "A minimal draft record with malformed published metadata.",
        "attack_class": "test",
        "behavioral_fingerprint": "test",
        "references": [{"title": "Example", "url": "https://example.com"}],
        "published": "not-a-date-time",
    }

    errors = validate_records.check_schema(record, validator)

    assert any("not-a-date-time" in error for error in errors)


# --- crosswalk pin declarations -------------------------------------------------
#
# The three states an endpoint can be in, and the checks that keep them apart:
# pinned (carries commit), declared unpinnable (says so, with a reason and a date,
# and is refutable), or neither, which is the blank the warning is about.


def crosswalk_validator():
    schema = json.loads(validate_crosswalks.SCHEMA_PATH.read_text(encoding="utf-8"))
    return validate_crosswalks.build_validator(schema)


def crosswalk_document(source: dict, target: dict | None = None) -> dict:
    """A crosswalk carrying only what the schema requires, plus the endpoints
    under test, so that a refusal can only have come from the endpoint."""
    return {
        "$schema": "https://aveproject.org/schema/crosswalk-1.0.0.schema.json",
        "source": source,
        "target": target or {"url": "https://aveproject.org"},
        "generated": "2026-08-09",
        "note": "Fixture crosswalk, endpoints only.",
        "mappings": [{"ave_id": "AVE-2026-00001"}],
        "coverage": {"mapped": 1},
    }


UNPINNABLE_SITE = {
    "url": "https://owasp.org/www-project-agentic-skills-top-10/",
    "pin_status": "unpinnable",
    "unpinnable_reason": "published as a site with no repository behind it",
    "checked_against_live_site": "2026-08-09",
    "content_digest": "sha256:" + "0" * 64,
}


def test_every_crosswalk_in_the_repository_still_validates():
    validator = crosswalk_validator()
    paths = sorted(validate_crosswalks.CROSSWALKS_DIR.glob("*.json"))

    assert paths, "no crosswalks found to validate"
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        assert validate_crosswalks.check_schema(document, validator) == [], path


def test_schema_accepts_a_declared_unpinnable_endpoint():
    document = crosswalk_document({"url": "https://aveproject.org"}, dict(UNPINNABLE_SITE))

    assert validate_crosswalks.check_schema(document, crosswalk_validator()) == []


@pytest.mark.parametrize("dropped", ["unpinnable_reason", "checked_against_live_site"])
def test_schema_rejects_an_unpinnable_declaration_missing_its_evidence(dropped):
    endpoint = dict(UNPINNABLE_SITE)
    del endpoint[dropped]
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    errors = validate_crosswalks.check_schema(document, crosswalk_validator())

    assert any(dropped in error for error in errors)


def test_schema_rejects_an_endpoint_that_is_both_pinned_and_unpinnable():
    endpoint = dict(UNPINNABLE_SITE, commit="a" * 40)
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    assert validate_crosswalks.check_schema(document, crosswalk_validator()) != []


def test_schema_rejects_a_pin_status_other_than_unpinnable():
    endpoint = dict(UNPINNABLE_SITE, pin_status="pinned")
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    assert validate_crosswalks.check_schema(document, crosswalk_validator()) != []


def test_declaring_a_repository_unpinnable_fails():
    endpoint = dict(UNPINNABLE_SITE, url="https://github.com/aveproject/ave")
    document = crosswalk_document({"url": "https://aveproject.org"}, endpoint)

    problems = validate_crosswalks.check_declared_unpinnable_has_no_repository(document)

    assert len(problems) == 1
    assert "which can be pinned" in problems[0]


def test_declaring_a_site_with_no_repository_unpinnable_passes():
    document = crosswalk_document({"url": "https://aveproject.org"}, dict(UNPINNABLE_SITE))

    assert validate_crosswalks.check_declared_unpinnable_has_no_repository(document) == []


def test_a_forge_url_with_no_repository_path_is_not_a_repository():
    assert validate_crosswalks.is_repository_url("https://github.com/aveproject/ave")
    assert not validate_crosswalks.is_repository_url("https://github.com/aveproject")
    assert not validate_crosswalks.is_repository_url("https://aveproject.org/schema")


def test_a_stated_record_count_with_no_commit_warns():
    document = crosswalk_document({"url": "https://aveproject.org", "record_count": 76})

    warnings = validate_crosswalks.warn_stated_count_without_pin(document)

    assert len(warnings) == 1
    assert "cannot be re-derived" in warnings[0]


def test_a_stated_record_count_is_not_warned_about_when_pinned():
    document = crosswalk_document(
        {"url": "https://aveproject.org", "record_count": 76, "commit": "b" * 40}
    )

    assert validate_crosswalks.warn_stated_count_without_pin(document) == []


def test_a_stated_record_count_is_not_warned_about_when_declared_unpinnable():
    document = crosswalk_document(dict(UNPINNABLE_SITE, record_count=76))

    assert validate_crosswalks.warn_stated_count_without_pin(document) == []


def test_the_unpinned_count_check_is_a_warning_until_commit_is_required():
    """The escalation agreed in #94: warn while commit is optional, hard-fail when
    it is promoted at the next major. The constant is the switch, so this asserts
    which side of the promotion the repository is on, not a preference."""
    assert validate_crosswalks.UNPINNED_COUNT_IS_FATAL is False
