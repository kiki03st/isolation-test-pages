"""Validate local configuration without requiring external prerequisites."""

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LIMITS = {
    "collector_deadline_s": 12,
    "deadline_grace_s": 1,
    "max_redirects": 5,
    "runner_response_bytes": 1048576,
    "concurrency": 1,
}


@pytest.fixture
def config_data():
    return {
        "bases": {},
        "collector_url": None,
        "token_env": "ISOLATION_TEST_TOKEN",
        "ca_file": None,
        "limits": dict(DEFAULT_LIMITS),
        "capabilities": [],
        "evidence_dir": None,
        "backend_contract": None,
        "allow_loopback_http": False,
    }


@pytest.fixture
def write_config(tmp_path):
    def write(payload):
        path = tmp_path / "config.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    return write


def test_example_is_typed_and_has_unconfigured_external_connections(monkeypatch):
    from isolation_tests.config import load_config
    from isolation_tests.model import RuntimeConfig

    monkeypatch.delenv("ISOLATION_TEST_TOKEN", raising=False)
    config = load_config(REPO_ROOT / "tools/isolation-tests/config.example.json")

    assert isinstance(config, RuntimeConfig)
    assert config.bases == {}
    assert config.collector_url is None
    assert config.token_env == "ISOLATION_TEST_TOKEN"
    assert config.ca_file is None
    assert config.limits == DEFAULT_LIMITS
    assert config.capabilities == frozenset()
    assert isinstance(config.capabilities, frozenset)
    assert config.evidence_dir is None
    assert config.backend_contract is None
    assert config.allow_loopback_http is False


def test_missing_external_inputs_are_not_a_configuration_error(write_config):
    from isolation_tests.config import load_config
    from isolation_tests.model import RuntimeConfig

    config = load_config(write_config({}))
    assert isinstance(config, RuntimeConfig)
    assert config.bases == {}
    assert config.collector_url is None
    assert config.ca_file is None
    assert config.evidence_dir is None
    assert config.backend_contract is None


def test_explicitly_unset_token_is_valid(config_data, write_config):
    from isolation_tests.config import load_config

    config_data["token_env"] = None
    assert load_config(write_config(config_data)).token_env is None


def test_valid_config_preserves_urls_limits_capabilities_and_paths(
    config_data, write_config, tmp_path, monkeypatch
):
    from isolation_tests.config import load_config

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("synthetic CA path fixture", encoding="utf-8")
    evidence_dir = tmp_path / "future-evidence"
    backend_contract = tmp_path / "backend.json"
    backend_contract.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("SYNTHETIC_TEST_TOKEN", raising=False)
    config_data.update(
        bases={"pages": "https://tester.github.io/isolation-test-pages/"},
        collector_url="https://collector.example.invalid:8443/collect",
        token_env="SYNTHETIC_TEST_TOKEN",
        ca_file=str(ca_file),
        evidence_dir=str(evidence_dir),
        backend_contract=str(backend_contract),
        capabilities=["collector", "rendering"],
    )
    config_data["limits"]["collector_deadline_s"] = 12.5
    config_data["limits"]["deadline_grace_s"] = 0

    config = load_config(write_config(config_data))

    assert config.bases == config_data["bases"]
    assert config.collector_url == "https://collector.example.invalid:8443/collect"
    assert config.token_env == "SYNTHETIC_TEST_TOKEN"
    assert config.ca_file == ca_file
    assert config.evidence_dir == evidence_dir
    assert config.backend_contract == backend_contract
    assert config.capabilities == frozenset({"collector", "rendering"})
    assert config.limits["collector_deadline_s"] == 12.5
    assert config.limits["deadline_grace_s"] == 0


def test_plain_http_remote_target_is_rejected(write_config):
    from isolation_tests.config import load_config

    with pytest.raises(ValueError, match="HTTPS"):
        load_config(write_config({"bases": {"pages": "http://example.invalid/site/"}}))


@pytest.mark.parametrize("field", ["bases", "collector_url"])
@pytest.mark.parametrize(
    "url",
    [
        "http://remote.example.invalid/site/",
        "https://user@remote.example.invalid/site/",
        "https://user:synthetic@remote.example.invalid/site/",
        "https://remote.example.invalid/site/#fragment",
        "https://*.github.io/site/",
        "https://github.io/*",
        "ftp://remote.example.invalid/site/",
        "//remote.example.invalid/site/",
        "https:///missing-host",
        "https://remote.example.invalid:invalid/site/",
        "",
    ],
)
def test_unsafe_urls_are_rejected_in_all_connection_fields(
    config_data, write_config, field, url
):
    from isolation_tests.config import load_config

    config_data[field] = {"pages": url} if field == "bases" else url
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


@pytest.mark.parametrize(
    "url", ["http://localhost:8000/", "http://127.0.0.1:8000/", "http://[::1]:8000/"]
)
@pytest.mark.parametrize("field", ["bases", "collector_url"])
def test_loopback_http_requires_explicit_local_opt_in(config_data, write_config, field, url):
    from isolation_tests.config import load_config

    config_data[field] = {"pages": url} if field == "bases" else url
    with pytest.raises(ValueError):
        load_config(write_config(config_data))
    config_data["allow_loopback_http"] = True
    config = load_config(write_config(config_data))
    assert (config.bases["pages"] if field == "bases" else config.collector_url) == url


@pytest.mark.parametrize(
    "url",
    ["http://remote.example.invalid/", "http://localhost.example.invalid/", "http://127.0.0.1.example.invalid/"],
)
def test_local_opt_in_does_not_allow_remote_http(config_data, write_config, url):
    from isolation_tests.config import load_config

    config_data.update(allow_loopback_http=True, collector_url=url)
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


@pytest.mark.parametrize("payload", [[], None, "config", True])
def test_config_requires_an_object(write_config, payload):
    from isolation_tests.config import load_config

    with pytest.raises(ValueError):
        load_config(write_config(payload))


@pytest.mark.parametrize("key", ["unknown_option", "token", "api_token", "authorization"])
def test_unknown_and_literal_secret_fields_are_rejected(config_data, write_config, key):
    from isolation_tests.config import load_config

    config_data[key] = "synthetic-value"
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


@pytest.mark.parametrize("token_env", ["", "Bearer synthetic-token", "TOKEN=value", "token-name", "1TOKEN", "TOKEN\n"])
def test_token_env_accepts_only_environment_variable_names(config_data, write_config, token_env):
    from isolation_tests.config import load_config

    config_data["token_env"] = token_env
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bases", []),
        ("bases", {"pages": None}),
        ("bases", {"pages": 1}),
        ("collector_url", False),
        ("token_env", True),
        ("ca_file", False),
        ("limits", []),
        ("capabilities", "collector"),
        ("capabilities", [True]),
        ("evidence_dir", 1),
        ("backend_contract", []),
        ("allow_loopback_http", 1),
        ("allow_loopback_http", "true"),
        ("allow_loopback_http", None),
    ],
)
def test_config_field_types_are_not_coerced(config_data, write_config, field, value):
    from isolation_tests.config import load_config

    config_data[field] = value
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


@pytest.mark.parametrize("limit", list(DEFAULT_LIMITS))
@pytest.mark.parametrize("value", [True, False, "1", -1, None, float("inf"), float("nan")])
def test_limits_reject_booleans_negative_nonfinite_and_nonnumeric_values(
    config_data, write_config, limit, value
):
    from isolation_tests.config import load_config

    config_data["limits"][limit] = value
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


@pytest.mark.parametrize("limit", ["max_redirects", "runner_response_bytes", "concurrency"])
def test_count_and_byte_limits_require_integers(config_data, write_config, limit):
    from isolation_tests.config import load_config

    config_data["limits"][limit] = 1.5
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


def test_limits_reject_unknown_keys(config_data, write_config):
    from isolation_tests.config import load_config

    config_data["limits"]["collector_deadine_s"] = 12
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


@pytest.mark.parametrize("value", [0, 9])
def test_concurrency_is_bounded_by_runner_safety_limit(config_data, write_config, value):
    from isolation_tests.config import load_config

    config_data["limits"]["concurrency"] = value
    with pytest.raises(ValueError):
        load_config(write_config(config_data))


def test_configured_ca_must_be_an_existing_file(config_data, write_config, tmp_path):
    from isolation_tests.config import load_config

    for path in (tmp_path / "missing-ca.pem", tmp_path):
        config_data["ca_file"] = str(path)
        with pytest.raises(ValueError):
            load_config(write_config(config_data))


def test_invalid_config_json_is_rejected(tmp_path):
    from isolation_tests.config import load_config

    path = tmp_path / "config.json"
    path.write_text('{"bases":', encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(path)


@pytest.mark.parametrize("url", ["https://remote.invalid:0/", "https://remote.invalid:65536/", "https://remote.invalid:/", "https://remote.invalid/%23fragment", "https://remote.invalid/%2awildcard", "https://bad_host.invalid/", "https://remote.invalid/\\escape", "https://remote.invalid/\npath"])
def test_additional_ambiguous_connection_urls_are_rejected(write_config, url):
    from isolation_tests.config import load_config

    with pytest.raises(ValueError):
        load_config(write_config({"collector_url": url}))


def test_relative_local_paths_resolve_against_config_file(tmp_path, monkeypatch, write_config):
    from isolation_tests.config import load_config

    (tmp_path / "ca.pem").write_text("synthetic", encoding="utf-8")
    (tmp_path / "backend.json").write_text("{}", encoding="utf-8")
    path = write_config({"ca_file": "ca.pem", "evidence_dir": "future-evidence", "backend_contract": "backend.json"})
    monkeypatch.chdir(tmp_path.parent)
    config = load_config(path)
    assert config.ca_file == tmp_path / "ca.pem"
    assert config.evidence_dir == tmp_path / "future-evidence"
    assert config.backend_contract == tmp_path / "backend.json"


@pytest.mark.parametrize("name", ["ca_file", "evidence_dir", "backend_contract"])
@pytest.mark.parametrize("value", ["", "https://example.invalid/path", "path\x00name"])
def test_local_paths_require_nonempty_filesystem_paths(write_config, name, value):
    from isolation_tests.config import load_config

    with pytest.raises(ValueError):
        load_config(write_config({name: value}))


def test_config_rejects_duplicate_keys(tmp_path):
    from isolation_tests.config import load_config

    path = tmp_path / "config.json"
    path.write_text('{"bases": {}, "bases": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_config(path)


def test_future_backend_contract_is_a_later_prerequisite(write_config, tmp_path):
    from isolation_tests.config import load_config

    config = load_config(write_config({"backend_contract": "future-contract.json"}))
    assert config.backend_contract == tmp_path / "future-contract.json"
