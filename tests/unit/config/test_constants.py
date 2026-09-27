from codekavach.config import constants


def test_constant_types() -> None:
    strings = [
        "PROJECT_FILE_NAME",
        "USER_FILE_NAME",
        "POLICY_FILE_NAME",
        "POLICY_PUBKEY_FILE_NAME",
        "TRUST_STORE_FILE_NAME",
        "STATE_DIR_NAME",
        "ENV_PREFIX",
        "ENV_NESTED_DELIMITER",
        "KEYRING_SERVICE",
        "SCHEMA_ID",
        "POLICY_SCHEMA_ID",
    ]
    integers = ["CONFIG_VERSION", "POLICY_VERSION", "MAX_CONFIG_BYTES", "MAX_SECRET_FILE_BYTES"]
    for name in strings:
        assert isinstance(getattr(constants, name), str), name
    for name in integers:
        assert isinstance(getattr(constants, name), int), name


def test_values() -> None:
    assert constants.PROJECT_FILE_NAME == "codekavach.toml"
    assert constants.STATE_DIR_NAME == ".codekavach"
    assert constants.ENV_PREFIX == "CODEKAVACH_"
    assert constants.ENV_NESTED_DELIMITER == "__"
    assert constants.MAX_CONFIG_BYTES == 1_048_576
    assert constants.MAX_SECRET_FILE_BYTES == 65_536
    assert constants.CONFIG_VERSION == 1


def test_schema_ids() -> None:
    assert constants.SCHEMA_ID.endswith("docs/schemas/codekavach.schema.json")
    assert constants.POLICY_SCHEMA_ID.endswith("docs/schemas/codekavach-policy.schema.json")
    assert constants.SCHEMA_ID.startswith("https://raw.githubusercontent.com/")
