from __future__ import annotations
from privguard_api.db.session import Base, engine
from privguard_api import models  # noqa: F401

def init_db():
    Base.metadata.create_all(bind=engine)
