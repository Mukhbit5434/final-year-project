import sqlite3

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(conn, _rec):
    # Extraction jobs run for 15-45 minutes. Under the default rollback journal
    # a single writer blocks every reader for that entire window and the web
    # thread starts throwing "database is locked". WAL plus a real busy timeout
    # is what makes SQLite survivable here at all.
    if isinstance(conn, sqlite3.Connection):
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()