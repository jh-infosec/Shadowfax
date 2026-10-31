"""
PostgreSQL support (v0.32).

SQLite has carried Shadowfax this far and is still the default: one file, no
server, nothing to install. What it cannot do is let several processes write at
once -- every writer queues for one file lock -- which is the reason the README
has called Shadowfax "a local-development tool". Set

    SHADOWFAX_DATABASE_URL=postgresql://user:password@host:5432/shadowfax

and the same code runs on PostgreSQL instead.

The approach is deliberately small: `db.py` keeps its SQL, and this module gives
it a connection that behaves like the `sqlite3` one it was written against --
`execute` returning rows that work as both `row["name"]` and `row[0]`,
`lastrowid`, `rowcount`, `total_changes`, `in_transaction`, `executescript` --
translating the handful of SQLite-isms the queries use:

    ?                         ->  %s                (and a literal % doubled)
    datetime('now')           ->  the same UTC text format SQLite produces
    INSERT OR IGNORE ...      ->  INSERT ... ON CONFLICT DO NOTHING
    json_extract(c, '$.a.b')  ->  (c::jsonb #>> '{a,b}')
    x LIKE y                  ->  x ILIKE y         (SQLite's LIKE ignores case)
    BEGIN IMMEDIATE           ->  pg_advisory_xact_lock(...)
    PRAGMA table_info(t)      ->  information_schema.columns
    INTEGER PRIMARY KEY AUTOINCREMENT  ->  BIGSERIAL PRIMARY KEY
    TEXT                      ->  TEXT COLLATE "C"  (byte order, as SQLite sorts)

**`BEGIN IMMEDIATE` is the one that matters.** In SQLite it takes the database's
write lock before anything is read; the ledger head, sign-in failure counts,
the last-enabled-admin check and the two-factor step all rely on that to stop
two requests acting on the same read (v0.21). In PostgreSQL the same guarantee
is a transaction-scoped advisory lock: every code path that asked SQLite for the
write lock takes the same PostgreSQL lock, held until commit or rollback, and
the reads after it see everything committed before it.

Rather than a second set of queries to keep in step, there is one set and one
translator, and the whole API suite runs against both databases.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

# The single lock that stands in for SQLite's database-wide write lock.
WRITE_LOCK_KEY = 0x5AD0F4  # "shadowfax", roughly

_PLACEHOLDER = re.compile(r"\?")
_DATETIME_NOW = re.compile(r"datetime\('now'\)", re.IGNORECASE)
_INSERT_OR_IGNORE = re.compile(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", re.IGNORECASE)
_JSON_EXTRACT = re.compile(r"json_extract\(\s*([\w.]+)\s*,\s*'\$\.([\w.]+)'\s*\)", re.IGNORECASE)
_LIKE = re.compile(r"(?<![\w])LIKE(?![\w])")
_PRAGMA_TABLE_INFO = re.compile(r"^\s*PRAGMA\s+table_info\((\w+)\)\s*$", re.IGNORECASE)
_PRAGMA_OTHER = re.compile(r"^\s*PRAGMA\b", re.IGNORECASE)
_BEGIN_IMMEDIATE = re.compile(r"^\s*BEGIN\s+IMMEDIATE\s*$", re.IGNORECASE)
_SQLITE_MASTER = re.compile(
    r"SELECT\s+name\s+FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'\s+AND\s+name\s*=\s*'(\w+)'",
    re.IGNORECASE)
_INSERT_TABLE = re.compile(r"^\s*INSERT\s+INTO\s+(\w+)", re.IGNORECASE)
_AUTOINC = re.compile(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", re.IGNORECASE)
_TEXT_TYPE = re.compile(r"(?<=\s)TEXT\b(?!\s+COLLATE)")
NOW_TEXT = "to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')"


def translate(sql: str) -> str:
    """One SQLite statement as PostgreSQL. Pure, so it can be tested alone."""
    m = _PRAGMA_TABLE_INFO.match(sql)
    if m:
        return ("SELECT column_name AS name, data_type AS type FROM information_schema.columns "
                f"WHERE table_schema = current_schema() AND table_name = '{m.group(1).lower()}' "
                "ORDER BY ordinal_position")
    if _BEGIN_IMMEDIATE.match(sql):
        return f"SELECT pg_advisory_xact_lock({WRITE_LOCK_KEY})"
    sql = _SQLITE_MASTER.sub(
        lambda m: ("SELECT table_name AS name FROM information_schema.tables "
                   f"WHERE table_schema = current_schema() AND table_name = '{m.group(1).lower()}'"), sql)
    sql = sql.replace("%", "%%")
    sql = _DATETIME_NOW.sub(NOW_TEXT, sql)
    sql = _JSON_EXTRACT.sub(lambda m: f"({m.group(1)}::jsonb #>> '{{{m.group(2).replace('.', ',')}}}')", sql)
    sql = _LIKE.sub("ILIKE", sql)
    if _INSERT_OR_IGNORE.search(sql):
        sql = _INSERT_OR_IGNORE.sub("INSERT INTO", sql).rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    sql = _PLACEHOLDER.sub("%s", sql)
    return sql


def translate_schema(script: str) -> list[str]:
    """The CREATE script as PostgreSQL statements: serial ids, byte-order text."""
    script = re.sub(r"--[^\n]*", "", script)
    script = _AUTOINC.sub("BIGSERIAL PRIMARY KEY", script)
    script = _TEXT_TYPE.sub('TEXT COLLATE "C"', script)
    script = _DATETIME_NOW.sub(NOW_TEXT, script)
    return [s.strip() for s in script.split(";") if s.strip()]


class Row(dict):
    """A row that answers to both row["column"] and row[0], like sqlite3.Row."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class Cursor:
    def __init__(self, cur, lastrowid: int | None):
        self._cur = cur
        self.lastrowid = lastrowid
        self.rowcount = cur.rowcount

    def _wrap(self, rec):
        if rec is None:
            return None
        return Row(zip([d.name for d in self._cur.description], rec))

    def fetchone(self):
        if self._cur.description is None:
            return None
        return self._wrap(self._cur.fetchone())

    def fetchall(self):
        if self._cur.description is None:
            return []
        names = [d.name for d in self._cur.description]
        return [Row(zip(names, r)) for r in self._cur.fetchall()]

    def __iter__(self) -> Iterator[Row]:
        return iter(self.fetchall())


class Connection:
    """The subset of sqlite3.Connection that db.py and app.py use."""

    def __init__(self, url: str, serial_tables: frozenset[str]):
        import psycopg
        self._pg = psycopg.connect(url, autocommit=False)
        self._serial = serial_tables
        self.total_changes = 0

    @property
    def in_transaction(self) -> bool:
        from psycopg.pq import TransactionStatus
        return self._pg.info.transaction_status != TransactionStatus.IDLE

    def execute(self, sql: str, params: tuple | list = ()) -> Cursor:
        if _PRAGMA_OTHER.match(sql) and not _PRAGMA_TABLE_INFO.match(sql):
            return Cursor(self._pg.cursor(), None)      # PRAGMA foreign_keys etc.
        pg_sql = translate(sql)
        m = _INSERT_TABLE.match(sql)
        wants_id = (m is not None and m.group(1).lower() in self._serial
                    and "RETURNING" not in pg_sql.upper())
        if wants_id:
            pg_sql = pg_sql.rstrip().rstrip(";") + " RETURNING id"
        cur = self._pg.cursor()
        cur.execute(pg_sql, tuple(params))
        lastrowid = None
        if wants_id:
            got = cur.fetchone()
            lastrowid = got[0] if got else None
        if cur.rowcount and cur.rowcount > 0 and not sql.lstrip().upper().startswith("SELECT"):
            self.total_changes += cur.rowcount
        return Cursor(cur, lastrowid)

    def executemany(self, sql: str, seq) -> None:
        pg_sql = translate(sql)
        cur = self._pg.cursor()
        rows = [tuple(p) for p in seq]
        if rows:
            cur.executemany(pg_sql, rows)
            if cur.rowcount and cur.rowcount > 0:
                self.total_changes += cur.rowcount

    def executescript(self, script: str) -> None:
        cur = self._pg.cursor()
        for stmt in translate_schema(script):
            cur.execute(stmt)

    def commit(self) -> None:
        self._pg.commit()

    def rollback(self) -> None:
        self._pg.rollback()

    def close(self) -> None:
        self._pg.close()


def serial_tables(schema: str) -> frozenset[str]:
    """Tables whose id SQLite would hand out, so INSERTs report lastrowid."""
    out = set()
    for m in re.finditer(r"CREATE TABLE IF NOT EXISTS (\w+) \((.*?)\);", schema, re.S):
        if _AUTOINC.search(m.group(2)):
            out.add(m.group(1).lower())
    return frozenset(out)


def reset_schema(url: str) -> None:
    """Drop everything Shadowfax created. For tests, and for nothing else."""
    import psycopg
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("DROP SCHEMA IF EXISTS public CASCADE")
        c.execute("CREATE SCHEMA public")
