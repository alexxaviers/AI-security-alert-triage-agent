import os
import sys
from pathlib import Path

# Deterministic, offline settings for every test. Must be set before app modules import.
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite:///" + str(Path(__file__).parent / "test.db"))
os.environ["INTEL_MODE"] = "fixtures"
os.environ["EMBEDDING_BACKEND"] = "tfidf"
os.environ["TRIAGE_ENGINE"] = "baseline"
os.environ.pop("ANTHROPIC_API_KEY", None)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402


@pytest.fixture(autouse=True, scope="session")
def _db():
    from app.db import Base, engine, init_db

    Base.metadata.drop_all(engine)
    init_db()
    yield
    Base.metadata.drop_all(engine)
    db_file = Path(__file__).parent / "test.db"
    if db_file.exists():
        db_file.unlink()
