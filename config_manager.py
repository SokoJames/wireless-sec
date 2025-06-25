"""
config_manager.py

Handles loading, validating, and saving configuration files (JSON or YAML).
Provides a dictionary-like interface for settings and supports safe, atomic updates.
Emphasizes security, error handling, and educational clarity.
"""

import json
import os
import shutil
import logging
from typing import Any, Optional, Dict

try:
    import yaml  # Optional YAML support
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

class ConfigManager:
    """
    Manages application configuration from JSON or YAML files.
    Supports validation, safe updates, and dictionary-like access.
    """
    def __init__(self, config_path: str, default_config: Dict[str, Any], schema: Optional[Dict[str, Any]] = None, logger: Optional[logging.Logger] = None):
        self.config_path = config_path
        self.default_config = default_config.copy()
        self.schema = schema
        self.logger = logger or logging.getLogger("ConfigManager")
        self.config = self.default_config.copy()
        self.file_format = 'json' if config_path.endswith('.json') else 'yaml'
        self.load()
        if self.schema:
            self.validate()

    def load(self) -> None:
        """
        Load configuration from file, falling back to defaults if missing or invalid.
        """
        if not os.path.isfile(self.config_path):
            self.logger.warning(f"Config file {self.config_path} not found. Using defaults.")
            self.config = self.default_config.copy()
            return
        try:
            with open(self.config_path, 'r') as f:
                if self.file_format == 'json':
                    self.config = json.load(f)
                elif self.file_format == 'yaml' and HAS_YAML:
                    self.config = yaml.safe_load(f)
                else:
                    raise ValueError("YAML config requires PyYAML to be installed.")
            # Fill in missing defaults
            for k, v in self.default_config.items():
                self.config.setdefault(k, v)
            self.logger.info(f"Loaded config from {self.config_path}")
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}. Using defaults.")
            self.config = self.default_config.copy()

    def save(self) -> None:
        """
        Save configuration to file atomically to prevent corruption.
        """
        tmp_path = self.config_path + ".tmp"
        try:
            with open(tmp_path, 'w') as f:
                if self.file_format == 'json':
                    json.dump(self.config, f, indent=2)
                elif self.file_format == 'yaml' and HAS_YAML:
                    yaml.safe_dump(self.config, f)
                else:
                    raise ValueError("YAML config requires PyYAML to be installed.")
            shutil.move(tmp_path, self.config_path)
            self.logger.info(f"Config saved to {self.config_path}")
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key, with optional default.
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any, autosave: bool = True) -> None:
        """
        Set a configuration value and optionally save.
        """
        self.config[key] = value
        if autosave:
            self.save()

    def reload(self) -> None:
        """
        Reload configuration from file.
        """
        self.load()

    def validate(self) -> bool:
        """
        Validate configuration against a schema (if provided).
        Returns True if valid, False otherwise.
        """
        if not self.schema:
            return True
        try:
            import jsonschema
            jsonschema.validate(instance=self.config, schema=self.schema)
            self.logger.info("Config validated against schema.")
            return True
        except ImportError:
            self.logger.warning("jsonschema not installed; skipping schema validation.")
            return True
        except Exception as e:
            self.logger.error(f"Config validation failed: {e}")
            return False

    def as_dict(self) -> Dict[str, Any]:
        """
        Return the current config as a dictionary.
        """
        return self.config.copy()

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Config Manager Test")
    parser.add_argument('--config', type=str, required=True, help='Path to config file (json or yaml)')
    parser.add_argument('--set', nargs=2, metavar=('KEY', 'VALUE'), help='Set a config value and save')
    parser.add_argument('--get', type=str, help='Get a config value')
    args = parser.parse_args()
    defaults = {"threshold": 10, "authorized_macs": [], "log_level": "INFO"}
    cm = ConfigManager(args.config, defaults)
    if args.set:
        key, value = args.set
        cm.set(key, value)
        print(f"Set {key} = {value}")
    if args.get:
        val = cm.get(args.get)
        print(f"{args.get} = {val}")
    if not args.set and not args.get:
        print("Config:", cm.as_dict())
