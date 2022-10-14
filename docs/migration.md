# Migration Guide

This document describes breaking changes to be aware of when switching versions.

## Migrating to v0.1

### Python Version Change

v0.1 drops support for Python 2.7 and earlier. Tested on Python 3.8 or higher.

### Module implementation

Run with

```bash
python3 -m autoscan {sections,server,authorize}
```

instead of

```bash
python3 scan.py {sections,server,authorize}
```

### Rewrite google drive module

```json
"GOOGLE": {
  "TEAMDRIVE": false,
  "TEAMDRIVES": []
}
```

has been deprecated. Instead, use

```json
"GOOGLE": {
  "DRIVES": {
    "MY_DRIVE": true,
    "SHARED_DRIVES": false,
    "SHARED_DRIVES_LIST": []
  }
}
```

to selectively accept changes from drives associated with an authorized user.

Due to the changes in google drive module, `cache.db` is **NOT** backward-compartible.

`userRateLimitExceeded` error from google drive api has been fixed using retry functionality implemented in google-api-python-client, which still needs to be further improved.

#### Use 'client secrets file' for authorization

Download 'client secrets file' from your api console and use its file location while proceeding

```bash
python3 -m autoscan authorize
```

Obviously, `GOOGLE.CLIENT_ID` and `GOOGLE.CLIENT_SECRET` in `config.json` have been deprecated.

#### Support 'service account file'

Specify a location of 'service account file' or its contents (JSON formatted string) to `GOOGLE.SERVICE_ACCOUNT_FILE` in `config.json` for api authorization. This will take priority over OAuth 2.0 for authorization.

### Removed

* `SERVER_ALLOW_MANUAL_SCAN` in `config.json` and WebUI have been removed. Instead, use POST requests which is always enabled.
* Drop support for connection with *-arrs. (Added back in v0.2.0)
