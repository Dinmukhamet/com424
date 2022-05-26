from peewee import Model, CharField, IntegerField, SqliteDatabase

db = SqliteDatabase(":memory:")


class Intruder(Model):
    scan_type = CharField()
    host = CharField()
    port = IntegerField(int)
    has_attacked = IntegerField(int)

    class Meta:
        database = db
