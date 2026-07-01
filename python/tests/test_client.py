"""Offline behaviour tests for the Client surface.

These never reach a live Vault: the fixture config points at a closed port, so
auth/read calls categorise as Unreachable, and the no-token path categorises as
LoginRequired. Identity, config-load errors, and handle lifecycle need no
network at all.
"""

import dotvault
import pytest


def test_default_config_path_nonempty():
    assert dotvault.default_config_path()


def test_construct_with_missing_config_raises():
    with pytest.raises(dotvault.DotvaultError) as exc:
        dotvault.Client(config_path="/nonexistent/dotvault/config.yaml")
    # A load failure is a bare DotvaultError, not a sentinel subclass.
    assert type(exc.value) is dotvault.DotvaultError


def test_identity_override_is_used(config_file):
    with dotvault.Client(config_path=config_file, identity="alice") as c:
        assert c.identity_name() == "alice"


def test_identity_defaults_to_os_user(config_file):
    with dotvault.Client(config_path=config_file) as c:
        # We can't assert the exact OS user portably, only that it resolves to
        # a non-empty name and never raises.
        assert c.identity_name()


def test_token_empty_before_auth(config_file):
    with dotvault.Client(config_path=config_file) as c:
        assert c.token() == ""


def test_authenticate_cached_without_token_is_login_required(config_file, monkeypatch):
    monkeypatch.delenv("DOTVAULT_TOKEN", raising=False)
    with dotvault.Client(config_path=config_file) as c:
        with pytest.raises(dotvault.LoginRequired):
            # Short timeout: with no token it never reaches the network anyway.
            c.authenticate_cached(timeout=2)


def test_authenticate_cached_with_token_against_dead_vault_is_unreachable(
    config_file, monkeypatch
):
    monkeypatch.setenv("DOTVAULT_TOKEN", "s.fake-token")
    with dotvault.Client(config_path=config_file) as c:
        with pytest.raises(dotvault.Unreachable):
            c.authenticate_cached(timeout=2)


def test_read_user_secret_against_dead_vault_is_unreachable(config_file):
    with dotvault.Client(config_path=config_file) as c:
        with pytest.raises(dotvault.Unreachable):
            c.read_user_secret("gh", "oauth_token", timeout=2)


def test_read_kv_field_against_dead_vault_is_unreachable(config_file):
    # Exercises the other read entry point (different C arg shape: explicit
    # mount/path) and its found-out plumbing. The found==True/value path needs
    # a live Vault and is covered by the integration story, not here.
    with dotvault.Client(config_path=config_file) as c:
        with pytest.raises(dotvault.Unreachable):
            c.read_kv_field("kv", "users/alice/gh", "oauth_token", timeout=2)


def test_use_after_close_raises(config_file):
    c = dotvault.Client(config_path=config_file)
    c.close()
    with pytest.raises(dotvault.DotvaultError):
        c.identity_name()


def test_close_is_idempotent(config_file):
    c = dotvault.Client(config_path=config_file)
    c.close()
    c.close()  # must not raise or double-free


def test_context_manager_closes(config_file):
    with dotvault.Client(config_path=config_file) as c:
        assert c.identity_name()
    with pytest.raises(dotvault.DotvaultError):
        c.identity_name()
