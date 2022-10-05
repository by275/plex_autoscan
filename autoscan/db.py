import os
import time
import logging
from typing import Tuple

import peewee as pw
from peewee import fn

logger = logging.getLogger("DB")


class QueueItemModel(pw.Model):
    scan_path = pw.CharField(max_length=256, unique=True, null=False)
    scan_for = pw.CharField(max_length=64, null=False)
    scan_section = pw.IntegerField(null=False)
    scan_type = pw.CharField(max_length=64, null=False)

    @classmethod
    def init(cls, path: str) -> None:
        database = pw.SqliteDatabase(path)
        cls.bind(database)
        if not os.path.exists(path):
            database.create_tables([cls])
            logger.info("Created Autoscan database tables.")
        if database.is_closed():
            database.connect()

    @classmethod
    def get_or_add(cls, **kwargs) -> Tuple[bool, pw.Model]:
        """add item if its scan path does not exist in db"""
        file_path = kwargs.get("scan_path")
        dir_path = os.path.dirname(file_path) if "." in file_path else file_path
        query = cls.select().where(fn.LOWER(cls.scan_path).contains(dir_path.lower()))

        try:
            return False, query.get()
        except cls.DoesNotExist:
            try:
                with cls._meta.database.atomic():
                    return True, cls.create(**kwargs)
            except pw.IntegrityError as exc:
                try:
                    return False, query.get()
                except cls.DoesNotExist:
                    raise exc from exc
            except Exception:
                logger.exception("Exception adding '%s' to database:", file_path)
                return False, None

    @classmethod
    def delete_by_path(cls, path: str, loglevel: int = logging.INFO) -> bool:
        try:
            cls.delete().where(cls.scan_path == path).execute()
            logger.log(loglevel, "Removed '%s' from Autoscan database.", path)
            time.sleep(1)
            return True
        except Exception:
            logger.exception("Exception deleting '%s' from Autoscan database:", path)
            return False

    @classmethod
    def count(cls) -> int:
        try:
            return cls.select().count()
        except Exception:
            logger.exception("Exception retrieving queued count:")
            return 0
