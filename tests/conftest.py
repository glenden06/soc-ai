"""Shared pytest fixtures. Every test runs against a throwaway SQLite file."""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (ROOT, os.path.join(ROOT, "parser"), os.path.join(ROOT, "engine"),
             os.path.join(ROOT, "llm_agent"), os.path.join(ROOT, "api")):
    if path not in sys.path:
        sys.path.insert(0, path)


@pytest.fixture()
def db_path(tmp_path, monkeypatch):
    """Point every module at an isolated database."""
    target = str(tmp_path / "test.db")
    monkeypatch.setenv("SOCAI_DB", target)
    return target


@pytest.fixture()
def conn(db_path):
    """Return an initialised connection to the throwaway database."""
    from common import db
    connection = db.init_db(db_path)
    yield connection
    connection.close()
