"""Map a behavior description to the closest MITRE ATT&CK techniques with vector embeddings.

Technique names + descriptions (data/attack_techniques.json, built from
github.com/mitre/cti) are embedded once and cached to disk. A query is embedded
the same way and ranked by cosine similarity.

Backends:
  sentence-transformers  all-MiniLM-L6-v2 by default, runs locally on CPU (preferred)
  tfidf                  scikit-learn TF-IDF; no model download, used as a fallback and in CI
"""

from __future__ import annotations

import json
import logging
import threading
from functools import lru_cache

import numpy as np

from app.config import DATA_DIR, get_settings

log = logging.getLogger(__name__)
CACHE_DIR = DATA_DIR / ".cache"


@lru_cache
def techniques() -> list[dict]:
    return json.loads((DATA_DIR / "attack_techniques.json").read_text())


@lru_cache
def technique_index() -> dict[str, dict]:
    return {t["id"]: t for t in techniques()}


def _doc(t: dict) -> str:
    return f"{t['name']}. {t['description']}"


class _STBackend:
    name = "sentence-transformers"

    def __init__(self, model_name: str):
        from sentence_transformers import SentenceTransformer  # optional dependency

        self.model = SentenceTransformer(model_name)
        safe = model_name.replace("/", "_")
        cache = CACHE_DIR / f"attack_{safe}_{len(techniques())}.npy"
        if cache.exists():
            self.matrix = np.load(cache)
        else:
            self.matrix = self.embed([_doc(t) for t in techniques()])
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            np.save(cache, self.matrix)

    def embed(self, texts: list[str]) -> np.ndarray:
        return np.asarray(self.model.encode(texts, normalize_embeddings=True, batch_size=64))


class _TfidfBackend:
    name = "tfidf"

    def __init__(self):
        from sklearn.feature_extraction.text import TfidfVectorizer

        # Weight names more heavily by repeating them.
        docs = [f"{t['name']} {t['name']} {t['description']}" for t in techniques()]
        self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True, min_df=1)
        m = self.vec.fit_transform(docs)
        self.matrix = m

    def embed(self, texts: list[str]):
        return self.vec.transform(texts)


_backend = None
_lock = threading.Lock()


def get_backend():
    global _backend
    with _lock:
        if _backend is None:
            s = get_settings()
            if s.embedding_backend in ("auto", "sentence-transformers"):
                try:
                    _backend = _STBackend(s.embedding_model)
                except Exception as e:  # missing package or no network for the model download
                    if s.embedding_backend == "sentence-transformers":
                        raise
                    log.warning("sentence-transformers unavailable (%s); using TF-IDF fallback", e)
            if _backend is None:
                _backend = _TfidfBackend()
        return _backend


def map_to_attack(description: str, top_k: int = 5) -> dict:
    b = get_backend()
    q = b.embed([description])
    if b.name == "tfidf":
        scores = (b.matrix @ q.T).toarray().ravel()
    else:
        scores = b.matrix @ q[0]
    top = np.argsort(-scores)[:top_k]
    matches = []
    for i in top:
        t = techniques()[int(i)]
        matches.append({"technique_id": t["id"], "name": t["name"], "tactics": t["tactics"],
                        "similarity": round(float(scores[i]), 3), "description": t["description"][:240]})
    return {"query": description[:300], "backend": b.name, "matches": matches}
