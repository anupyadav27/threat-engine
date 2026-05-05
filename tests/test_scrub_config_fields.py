"""Tests for scrub_config_fields() shared utility."""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared", "common"))

from scrub_config import scrub_config_fields, _REDACTED


class TestFlatDict:
    def test_matching_key_value_redacted(self):
        result = scrub_config_fields({"password": "hunter2"})
        assert result == {"password": _REDACTED}

    def test_non_matching_key_unchanged(self):
        result = scrub_config_fields({"name": "my-bucket", "region": "us-east-1"})
        assert result == {"name": "my-bucket", "region": "us-east-1"}

    def test_multiple_keys_mixed(self):
        result = scrub_config_fields({"name": "db", "password": "secret123", "port": 5432})
        assert result["name"] == "db"
        assert result["password"] == _REDACTED
        assert result["port"] == 5432

    def test_access_key_id_redacted(self):
        result = scrub_config_fields({"access_key_id": "AKIAIOSFODNN7EXAMPLE"})
        assert result["access_key_id"] == _REDACTED

    def test_api_key_redacted(self):
        result = scrub_config_fields({"api_key": "sk-abc123"})
        assert result["api_key"] == _REDACTED

    def test_private_key_redacted(self):
        result = scrub_config_fields({"private_key": "-----BEGIN RSA PRIVATE KEY-----"})
        assert result["private_key"] == _REDACTED

    def test_token_redacted(self):
        result = scrub_config_fields({"token": "eyJhbGci..."})
        assert result["token"] == _REDACTED

    def test_connection_string_redacted(self):
        result = scrub_config_fields({"connection_string": "postgres://user:pass@host/db"})
        assert result["connection_string"] == _REDACTED

    def test_jdbc_redacted(self):
        result = scrub_config_fields({"jdbc": "jdbc:postgresql://host:5432/db"})
        assert result["jdbc"] == _REDACTED


class TestCaseInsensitiveKeys:
    def test_uppercase_key_redacted(self):
        result = scrub_config_fields({"PASSWORD": "secret"})
        assert result["PASSWORD"] == _REDACTED

    def test_mixed_case_key_redacted(self):
        result = scrub_config_fields({"DbPassword": "secret"})
        assert result["DbPassword"] == _REDACTED

    def test_key_containing_sensitive_substring(self):
        result = scrub_config_fields({"db_password_hash": "abc123"})
        assert result["db_password_hash"] == _REDACTED


class TestNestedDict:
    def test_nested_dict_recursive(self):
        data = {"outer": {"password": "p@ssw0rd", "name": "inner"}}
        result = scrub_config_fields(data)
        assert result["outer"]["password"] == _REDACTED
        assert result["outer"]["name"] == "inner"

    def test_deeply_nested(self):
        data = {"a": {"b": {"c": {"secret_key": "xyz"}}}}
        result = scrub_config_fields(data)
        assert result["a"]["b"]["c"]["secret_key"] == _REDACTED

    def test_non_sensitive_nested_unchanged(self):
        data = {"config": {"host": "localhost", "port": 5432}}
        result = scrub_config_fields(data)
        assert result == data


class TestListHandling:
    def test_list_of_dicts(self):
        data = [{"password": "p1"}, {"name": "ok"}]
        result = scrub_config_fields(data)
        assert result[0]["password"] == _REDACTED
        assert result[1]["name"] == "ok"

    def test_list_of_scalars_unchanged(self):
        data = [1, "two", None, True]
        result = scrub_config_fields(data)
        assert result == data

    def test_tag_map_with_sensitive_key(self):
        data = {"tags": {"password": "whoops", "env": "prod"}}
        result = scrub_config_fields(data)
        assert result["tags"]["password"] == _REDACTED
        assert result["tags"]["env"] == "prod"


class TestEdgeCases:
    def test_none_input(self):
        assert scrub_config_fields(None) is None

    def test_empty_dict(self):
        assert scrub_config_fields({}) == {}

    def test_empty_list(self):
        assert scrub_config_fields([]) == []

    def test_scalar_int(self):
        assert scrub_config_fields(42) == 42

    def test_scalar_string(self):
        assert scrub_config_fields("hello") == "hello"

    def test_already_redacted_value(self):
        result = scrub_config_fields({"password": _REDACTED})
        assert result["password"] == _REDACTED

    def test_list_inside_dict_inside_list(self):
        # "credentials" key is sensitive — entire value (the list) is redacted
        data = [{"credentials": [{"token": "secret"}]}]
        result = scrub_config_fields(data)
        assert result[0]["credentials"] == _REDACTED

    def test_nested_sensitive_key_within_non_sensitive_key(self):
        # Non-sensitive outer key — recurse into list, find token key inside
        data = [{"storage_config": [{"token": "secret", "endpoint": "http://..."}]}]
        result = scrub_config_fields(data)
        assert result[0]["storage_config"][0]["token"] == _REDACTED
        assert result[0]["storage_config"][0]["endpoint"] == "http://..."
