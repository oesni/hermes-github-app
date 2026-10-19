"""Strict YAML 1.2 configuration parsing. No filesystem or credential loading."""
from dataclasses import dataclass
import os
import re
from ruamel.yaml import YAML
from ruamel.yaml.nodes import MappingNode, ScalarNode, SequenceNode
from ruamel.yaml.tokens import AliasToken, AnchorToken, DirectiveToken, TagToken
from .policy import Policy, PolicyError


class ConfigError(ValueError):
    """Safe administrator-facing error; never contains rejected values."""


@dataclass(frozen=True)
class AuthConfig:
    app_id: int
    installation_id: int
    private_key_path: str


@dataclass(frozen=True)
class Config:
    version: int
    auth: AuthConfig
    policy: Policy


def _mapping(value, allowed, required=frozenset()):
    if not isinstance(value, dict) or value.keys() - allowed or not required <= value.keys():
        raise ConfigError("configuration field/type error")
    return value


def _positive(value):
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise ConfigError("configuration integer field error")
    return value


def _convert(node):
    if isinstance(node, MappingNode):
        result = {}
        for key, value in node.value:
            if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str" or key.value == "<<":
                raise ConfigError("configuration mapping key error")
            if key.value in result:
                raise ConfigError("duplicate configuration mapping key")
            result[key.value] = _convert(value)
        return result
    if isinstance(node, SequenceNode):
        return [_convert(child) for child in node.value]
    if not isinstance(node, ScalarNode):
        raise ConfigError("configuration YAML node error")
    if node.tag == "tag:yaml.org,2002:str":
        if "\x00" in node.value or any(0xD800 <= ord(c) <= 0xDFFF for c in node.value):
            raise ConfigError("configuration string field error")
        return node.value
    if node.tag == "tag:yaml.org,2002:int":
        if node.style is not None or not re.fullmatch(r"[1-9][0-9]*", node.value):
            raise ConfigError("configuration integer syntax error")
        try:
            return int(node.value)
        except ValueError:
            raise ConfigError("configuration integer field error") from None
    if node.tag == "tag:yaml.org,2002:bool":
        return node.value.lower() == "true"
    # No schema field admits null, floating point, timestamps, sets or binary.
    raise ConfigError("configuration field/type error")


def parse_config(text: str | bytes) -> Config:
    try:
        if isinstance(text, bytes):
            text = text.decode("utf-8", errors="strict")
        if not isinstance(text, str):
            raise ConfigError("configuration must be UTF-8 YAML")
        yaml = YAML(typ="safe", pure=True)
        yaml.version = (1, 2)
        for token in yaml.scan(text):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise ConfigError("YAML anchors, aliases and explicit tags are forbidden")
            if isinstance(token, DirectiveToken) and (token.name != "YAML" or token.value != (1, 2)):
                raise ConfigError("configuration requires YAML 1.2")
        data = _convert(yaml.compose(text))
    except ConfigError:
        raise
    except Exception:
        raise ConfigError("configuration YAML syntax or UTF-8 error") from None
    root = _mapping(data, {"version", "auth", "policy"}, {"version", "auth", "policy"})
    if type(root["version"]) is not int or root["version"] != 1:
        raise ConfigError("unsupported configuration version")
    auth = _mapping(root["auth"], {"app_id", "installation_id", "private_key_path"}, {"app_id", "installation_id", "private_key_path"})
    path = auth["private_key_path"]
    if not isinstance(path, str) or not path or "\x00" in path or not os.path.isabs(path):
        raise ConfigError("private_key_path must be an absolute path")
    auth_config = AuthConfig(_positive(auth["app_id"]), _positive(auth["installation_id"]), path)
    try:
        policy = Policy.from_dict(root["policy"])
    except PolicyError:
        raise ConfigError("configuration policy field/type/action error") from None
    return Config(1, auth_config, policy)
