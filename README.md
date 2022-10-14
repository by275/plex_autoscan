# Plex Autoscan

A maintained fork of [Plex Autoscan](https://github.com/l3uddz/plex_autoscan)

- [Migration Guide](docs/migration.md)
- [Full Changelog](docs/CHANGELOG.md)

## Introduction

Plex Autoscan is a python script that assists in the importing of Sonarr, Radarr, and Lidarr downloads into Plex Media Server.

It does this by creating a web server to accept webhook requests from these apps, and in turn, sends a scan request to Plex. Plex will then only scan the parent folder (i.e. season folder for TV shows, movie folder for movies, and album folders for music) of the media file (versus scanning the entire library folder).

In addition to the above, Plex Autoscan can also monitor Google Drive for updates. When a new file is detected, it is checked against the Plex database and if this file is missing, a new scan request is sent to Plex (see section [below](README.md#google-drive-monitoring)).

Plex Autoscan is installed on the same server as the Plex Media Server.

## Requirements

- Ubuntu/Debian
- Python 3.8 or higher (`sudo apt install python3 python3-pip`).
- requirements.txt modules (see below).

## Installation

1. `cd /opt`
1. `git clone https://github.com/by275/plex_autoscan`
1. `cd plex_autoscan`
1. `sudo python -m pip install -r requirements.txt`
1. `python3 -m autoscan sections` - Run once to generate a default `config.json` file.
1. `/opt/plex_autoscan/config.json` - Configure settings (do this before moving on).
1. `sudo cp /opt/plex_autoscan/system/autoscan.service /etc/systemd/system/`
1. `sudo systemctl daemon-reload`
1. `sudo systemctl enable autoscan.service`
1. `sudo systemctl start autoscan.service`

### Installation with PIP

> _New in v0.1.0_

With a recent version of pip and git, it can be installed by

```bash
python3 -m pip install git+https://github.com/by275/plex_autoscan.git
```

and run with `autoscan`. Tags/Branches/Hashes can be specified like this:

```bash
python3 -m pip install git+https://github.com/by275/plex_autoscan.git@v0.1.0
python3 -m pip install git+https://github.com/by275/plex_autoscan.git@feat
```

Please find more details [here](https://pip.pypa.io/en/latest/topics/vcs-support/).

## Configuration

[Configuration Guide](docs/configuration.md)

## Setup

Setup instructions to connect Sonarr/Radarr/Lidarr to Plex Autoscan.

### Sonarr

1. Sonarr -> "Settings" -> "Connect".

1. Add a new "Webhook".

1. Add the following:

   1. Name: Plex Autoscan

   1. On Grab: `No`

   1. On Download: `Yes`

   1. On Upgrade: `Yes`

   1. On Rename: `Yes`

   1. Filter Series Tags: _Leave Blank_

   1. URL: _Your Plex Autoscan Webhook URL_

   1. Method:`POST`

   1. Username: _Leave Blank_

   1. Password: _Leave Blank_

1. The settings will look like this:

   ![Sonarr Plex Autoscan](https://i.imgur.com/F8L8R3a.png)

1. Click "Save" to add Plex Autoscan.

### Radarr

1. Radarr -> "Settings" -> "Connect".

1. Add a new "Webhook".

1. Add the following:

   1. Name: Plex Autoscan

   1. On Grab: `No`

   1. On Download: `Yes`

   1. On Upgrade: `Yes`

   1. On Rename: `Yes`

   1. Filter Movie Tags: _Leave Blank_

   1. URL: _Your Plex Autoscan Webhook URL_

   1. Method:`POST`

   1. Username: _Leave Blank_

   1. Password: _Leave Blank_

1. The settings will look like this:

   ![Radarr Plex Autoscan](https://i.imgur.com/jQJyvMA.png)

1. Click "Save" to add Plex Autoscan.

### Lidarr

1. Lidarr -> "Settings" -> "Connect".

1. Add a new "Webhook" Notification.

1. Add the following:

   1. Name: Plex Autoscan

   1. On Grab: `No`

   1. On Album Import: `No`

   1. On Track Import: `Yes`

   1. On Track Upgrade: `Yes`

   1. On Rename: `Yes`

   1. Tags: _Leave Blank_

   1. URL: _Your Plex Autoscan Webhook URL_

   1. Method:`POST`

   1. Username: _Leave Blank_

   1. Password: _Leave Blank_

1. The settings will look like this:

   ![Radarr Plex Autoscan](https://i.imgur.com/43uZloh.png)

1. Click "Save" to add Plex Autoscan.
