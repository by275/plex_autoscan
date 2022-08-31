__title__ = "Autoscan"
__author__ = "by275"
__url__ = "https://github.com/by275/plex_autoscan"
__description__ = "Script to assist in scanning Plex library more efficiently."
__license__ = "GNU General Public License v3.0"

__original_title__ = "Plex Autoscan"
__original_author__ = "l3uddz"
__original_url__ = "https://github.com/l3uddz/plex_autoscan"

try:
    from ._version import version
except ImportError:
    try:
        from setuptools_scm import get_version

        version = get_version(version_scheme="release-branch-semver")
    except Exception:
        version = "0.2.0.dev0"

__version__ = version
