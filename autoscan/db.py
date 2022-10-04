import logging
import os
from typing import Tuple

from peewee import Model, SqliteDatabase, CharField, IntegerField

logger = logging.getLogger("DB")


class QueueItemModel(Model):
    scan_path = CharField(max_length=256, unique=True, null=False)
    scan_for = CharField(max_length=64, null=False)
    scan_section = IntegerField(null=False)
    scan_type = CharField(max_length=64, null=False)

    @classmethod
    def init(cls, path: str) -> None:
        database = SqliteDatabase(path)
        cls.bind(database)
        if not os.path.exists(path):
            database.create_tables([cls])
            logger.info("Created Autoscan database tables.")
        if database.is_closed():
            database.connect()

    @classmethod
    def exists_file_root_path(cls, file_path: str) -> Tuple[bool, str]:
        dir_path = os.path.dirname(file_path) if "." in file_path else file_path
        for item in QueueItemModel.select():
            if dir_path.lower() in item.scan_path.lower():
                return True, item.scan_path
        return False, None

    @classmethod
    def add_item(cls, scan_path, scan_for, scan_section, scan_type):
        item = None
        try:
            return QueueItemModel.create(
                scan_path=scan_path,
                scan_for=scan_for,
                scan_section=scan_section,
                scan_type=scan_type,
            )
        except AttributeError:
            return item
        except Exception:
            pass
            # logger.exception("Exception adding %r to database: ", scan_path)
        return item

    @classmethod
    def delete_by_scan_path(cls, scan_path):
        try:
            return cls.delete().where(QueueItemModel.scan_path == scan_path).execute()
        except Exception:
            logger.exception("Exception deleting %r from Autoscan database: ", scan_path)
            return False

    @classmethod
    def count_all(cls):
        try:
            return QueueItemModel.select().count()
        except Exception:
            logger.exception("Exception retrieving queued count: ")
        return 0
