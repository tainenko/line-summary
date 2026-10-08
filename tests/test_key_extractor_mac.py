from unittest.mock import patch
import pytest
import key_extractor_mac as kex_mac


def test_validate_key_format_accepts_32_char_hex():
    assert kex_mac.validate_key_format("a" * 32) is True


def test_validate_key_format_rejects_wrong_length():
    assert kex_mac.validate_key_format("a" * 10) is False


def test_extract_key_raises_when_env_var_missing(monkeypatch):
    monkeypatch.delenv("LINE_DB_KEY", raising=False)
    with patch("db_reader.preflight_db_access"):
        with pytest.raises(RuntimeError, match="LINE_DB_KEY is not set"):
            kex_mac.extract_key("fake.edb", require_consent=False)


def test_extract_key_raises_on_malformed_env_var(monkeypatch):
    monkeypatch.setenv("LINE_DB_KEY", "not-hex")
    with patch("db_reader.preflight_db_access"):
        with pytest.raises(RuntimeError, match="not a valid"):
            kex_mac.extract_key("fake.edb", require_consent=False)


def test_extract_key_raises_when_key_does_not_decrypt(monkeypatch):
    monkeypatch.setenv("LINE_DB_KEY", "a" * 32)
    with patch("db_reader.preflight_db_access"), \
         patch("db_reader.probe_key", return_value=False):
        with pytest.raises(RuntimeError, match="did not decrypt"):
            kex_mac.extract_key("fake.edb", require_consent=False)


def test_extract_key_returns_lowercased_key_on_success(monkeypatch):
    monkeypatch.setenv("LINE_DB_KEY", "A" * 32)
    with patch("db_reader.preflight_db_access"), \
         patch("db_reader.probe_key", return_value=True):
        assert kex_mac.extract_key("fake.edb", require_consent=False) == "a" * 32


def test_extract_key_propagates_db_access_error(monkeypatch):
    monkeypatch.setenv("LINE_DB_KEY", "a" * 32)
    from db_reader import DbAccessError
    with patch("db_reader.preflight_db_access", side_effect=DbAccessError("locked")):
        with pytest.raises(RuntimeError, match="Cannot access the LINE database"):
            kex_mac.extract_key("fake.edb", require_consent=False)
