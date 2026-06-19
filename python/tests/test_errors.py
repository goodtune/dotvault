"""Unit tests for the error-category mapping (no native library required)."""

import dotvault
from dotvault import _errors


def test_category_codes_match_bridge_contract():
    # These integers are the wire contract with python/bridge/bridge.go; a drift
    # here means the Go and Python sides disagree on what a code means.
    assert _errors.CAT_OK == 0
    assert _errors.CAT_LOGIN_REQUIRED == 1
    assert _errors.CAT_DENIED == 2
    assert _errors.CAT_UNREACHABLE == 3
    assert _errors.CAT_AUTH_FAILED == 4
    assert _errors.CAT_OTHER == 5


def test_error_for_maps_each_category():
    assert isinstance(_errors.error_for(_errors.CAT_LOGIN_REQUIRED, "x"), dotvault.LoginRequired)
    assert isinstance(_errors.error_for(_errors.CAT_DENIED, "x"), dotvault.Denied)
    assert isinstance(_errors.error_for(_errors.CAT_UNREACHABLE, "x"), dotvault.Unreachable)
    assert isinstance(_errors.error_for(_errors.CAT_AUTH_FAILED, "x"), dotvault.AuthFailed)


def test_error_for_unknown_category_is_base_error():
    err = _errors.error_for(_errors.CAT_OTHER, "boom")
    assert type(err) is dotvault.DotvaultError
    assert "boom" in str(err)


def test_error_for_none_message_has_fallback():
    err = _errors.error_for(_errors.CAT_OTHER, None)
    assert str(err)


def test_subclasses_are_dotvault_errors():
    for cls in (dotvault.LoginRequired, dotvault.Denied, dotvault.Unreachable, dotvault.AuthFailed):
        assert issubclass(cls, dotvault.DotvaultError)
