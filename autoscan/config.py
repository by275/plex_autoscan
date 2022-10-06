import argparse
import errno
import json
import logging
import os
import sys
from copy import copy
from pathlib import Path

from autoscan import __description__, __title__, __url__, __version__
from autoscan.defaults import base_config, base_settings

logger = logging.getLogger("CONFIG")


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)

        return cls._instances[cls]


class Config:
    __metaclass__ = Singleton

    def __init__(self):
        """Initializes config"""
        # Args and settings
        self.args = self.parse_args()
        self.settings = self.get_settings()
        # Configs
        self.configs = None

    @property
    def default_config(self):
        cfg = copy(base_config)

        # add example scan priorities
        cfg["SERVER_SCAN_PRIORITIES"] = {"0": ["/Movies/"], "1": ["/TV/"], "2": ["/Music/"]}

        # add example file trash control files
        cfg["PLEX_EMPTY_TRASH_CONTROL_FILES"] = ["/mnt/unionfs/mounted.bin"]

        # add example server path mappings
        cfg["SERVER_PATH_MAPPINGS"] = {"/mnt/unionfs/": ["/home/user/media/fused/"]}

        # add example file exist path mappings
        cfg["SERVER_FILE_EXIST_PATH_MAPPINGS"] = {"/home/user/rclone/": ["/data/"]}
        # add example server ignore list
        cfg["SERVER_IGNORE_LIST"] = ["/.grab/", ".DS_Store", "Thumbs.db"]

        # add example allowed scan paths to google
        cfg["GOOGLE"]["ALLOWED"]["FILE_PATHS"] = ["My Drive/Media/Movies/", "My Drive/Media/TV/", "My Drive/Media/4K/"]

        # add example scan extensions to google
        cfg["GOOGLE"]["ALLOWED"]["FILE_EXTENSIONS"] = True
        cfg["GOOGLE"]["ALLOWED"]["FILE_EXTENSIONS_LIST"] = [
            "webm",
            "mkv",
            "flv",
            "vob",
            "ogv",
            "ogg",
            "drc",
            "gif",
            "gifv",
            "mng",
            "avi",
            "mov",
            "qt",
            "wmv",
            "yuv",
            "rm",
            "rmvb",
            "asf",
            "amv",
            "mp4",
            "m4p",
            "m4v",
            "mpg",
            "mp2",
            "mpeg",
            "mpe",
            "mpv",
            "m2v",
            "m4v",
            "svi",
            "3gp",
            "3g2",
            "mxf",
            "roq",
            "nsv",
            "f4v",
            "f4p",
            "f4a",
            "f4b",
            "mp3",
            "flac",
            "ts",
            "m2ts",
            "smi",
            "srt",
            "ass",
            "ssa",
            "vtt",
            "idx",
            "sub",
        ]

        # add example scan mimes for google
        cfg["GOOGLE"]["ALLOWED"]["MIME_TYPES"] = True
        cfg["GOOGLE"]["ALLOWED"]["MIME_TYPES_LIST"] = ["video"]

        # add example Rclone file exists to remote mappings
        cfg["RCLONE"]["RC_CACHE_REFRESH"]["FILE_EXISTS_TO_REMOTE_MAPPINGS"] = {"Media/": ["/mnt/rclone/Media/"]}

        cfg["PLEX_ASSET_EXTENSIONS"] = ["smi", "srt", "idx", "sub", "ass", "ssa", "vtt"]
        cfg["PLEX_EXTRA_DIRS"] = [
            "Behind The Scenes",
            "Deleted Scenes",
            "Featurettes",
            "Interviews",
            "Scenes",
            "Shorts",
            "Trailers",
            "Other",
        ]

        return cfg

    def __inner_upgrade(self, settings1, settings2, key=None, overwrite=False):
        sub_upgraded = False
        merged = copy(settings2)

        if isinstance(settings1, dict):
            for k, v in settings1.items():
                # missing k
                if k not in settings2:
                    merged[k] = v
                    sub_upgraded = True
                    if not key:
                        logger.info("Added %r config option: %s", str(k), str(v))
                    else:
                        logger.info("Added %r to config option %r: %s", str(k), str(key), str(v))
                    continue

                # iterate children
                if isinstance(v, (dict, list)):
                    merged[k], did_upgrade = self.__inner_upgrade(
                        settings1[k], settings2[k], key=k, overwrite=overwrite
                    )
                    sub_upgraded = did_upgrade if did_upgrade else sub_upgraded
                elif settings1[k] != settings2[k] and overwrite:
                    merged = settings1
                    sub_upgraded = True
        elif isinstance(settings1, list) and key:
            for v in settings1:
                if v not in settings2:
                    merged.append(v)
                    sub_upgraded = True
                    logger.info("Added to config option %r: %s", str(key), str(v))
                    continue

        return merged, sub_upgraded

    def upgrade_settings(self, currents):
        fields_env = {}

        # ENV gets priority: ENV > config.json
        for name, _ in base_config.items():
            if name in os.environ:
                # Use JSON decoder to get same behaviour as config file
                fields_env[name] = json.JSONDecoder().decode(os.environ[name])
                logger.info("Using ENV setting %s=%s", name, fields_env[name])

        # Update in-memory config with environment settings
        currents.update(fields_env)

        # Do inner upgrade
        upgraded_settings, upgraded = self.__inner_upgrade(base_config, currents)
        return upgraded_settings, upgraded

    def load(self):
        logger.debug("Upgrading config...")
        if not Path(self.settings["config"]).exists():
            logger.info("No config file found. Creating a default config...")
            self.save(self.default_config)

        with open(self.settings["config"], "r", encoding="utf-8") as fp:
            cfg, upgraded = self.upgrade_settings(json.load(fp))

            # Save config if upgraded
            if upgraded:
                self.save(cfg)
                sys.exit(0)
            else:
                logger.debug("Config was not upgraded as there were no changes to add.")

        self.configs = cfg

    def save(self, cfg, exitOnSave=True):
        with open(self.settings["config"], "w", encoding="utf-8") as fp:
            json.dump(cfg, fp, indent=2, sort_keys=True)
        if exitOnSave:
            logger.info(
                "Your config was upgraded. You may check the changes here: %r",
                self.settings["config"],
            )

        if exitOnSave:
            sys.exit(0)

    def get_settings(self):
        setts = {}
        for name, data in base_settings.items():
            # Argrument priority: cmd < environment < default
            try:
                # Command line argument
                if self.args[name]:
                    value = self.args[name]
                    logger.debug("setting from ARG   --%s=%s", name, value)

                # Envirnoment variable
                elif data["env"] in os.environ:
                    value = os.environ[data["env"]]
                    logger.debug("setting from ENV   --%s=%s", name, value)

                # Default
                else:
                    value = data["default"]
                    logger.debug("setting by default %s=%s", data["argv"], value)

                setts[name] = value

            except Exception:
                logger.exception("Exception retrieving setting value: %r", name)

        # checking existance of important files' dir
        for argname in ["config", "logfile", "queuefile", "cachefile"]:
            filepath = setts[argname]
            if filepath is not None and not Path(filepath).parent.exists():
                logger.error(FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), filepath))
                sys.exit(1)

        return setts

    # Parse command line arguments
    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=__title__,
            description=__description__,
            epilog=f"Online help: <{__url__}>",
            formatter_class=argparse.RawTextHelpFormatter,
        )

        # Mode
        parser.add_argument(
            "cmd",
            choices=(
                "sections",
                "sections+",
                "server",
                "authorize",
                "build_caches",
                "update_config",
            ),
            help=(
                '"sections": prints Plex Sections\n'
                '"sections+": prints Plex Sections with more details\n'
                '"server": starts the application\n'
                '"authorize": authorize against a Google account\n'
                '"build_caches": build complete Google Drive caches\n'
                '"update_config": perform upgrade of config'
            ),
        )

        # Display version info
        parser.add_argument(
            "-v",
            "--version",
            action="version",
            version=f"{__title__} v{__version__}",
        )

        # Config file
        parser.add_argument(
            base_settings["config"]["argv"],
            nargs="?",
            const=None,
            help=f'Config file location (default: {base_settings["config"]["default"]})',
        )

        # Log file
        parser.add_argument(
            base_settings["logfile"]["argv"],
            nargs="?",
            const=None,
            help=f'Log file location (default: {base_settings["logfile"]["default"]})',
        )

        # Queue file
        parser.add_argument(
            base_settings["queuefile"]["argv"],
            nargs="?",
            const=None,
            help=f'Queue file location (default: {base_settings["queuefile"]["default"]})',
        )

        # Cache file
        parser.add_argument(
            base_settings["cachefile"]["argv"],
            nargs="?",
            const=None,
            help=f'Google cache file location (default: {base_settings["cachefile"]["default"]})',
        )

        # Logging level
        parser.add_argument(
            base_settings["loglevel"]["argv"],
            choices=("WARN", "INFO", "DEBUG"),
            help=f'Log level (default: {base_settings["loglevel"]["default"]})',
        )

        # Print help by default if no arguments
        if len(sys.argv) == 1:
            parser.print_help()

            sys.exit(0)

        else:
            return vars(parser.parse_args())
