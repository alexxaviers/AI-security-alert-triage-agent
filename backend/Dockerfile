FROM python:3.12-slim

# true: bake in the local sentence-transformers model for the ATT&CK mapper (~1 GB image).
# false: TF-IDF fallback only (small image, fits free-tier hosts with 512 MB RAM).
ARG WITH_EMBEDDINGS=true

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/app/.hf

WORKDIR /app

COPY requirements.txt requirements-embeddings.txt ./
RUN pip install -r requirements.txt && \
    if [ "$WITH_EMBEDDINGS" = "true" ]; then \
      pip install torch --index-url https://download.pytorch.org/whl/cpu && \
      pip install -r requirements-embeddings.txt; \
    fi

COPY . .

# Download the model and pre-compute the ATT&CK technique embeddings at build time,
# so the container starts fast and never needs the network for them.
RUN if [ "$WITH_EMBEDDINGS" = "true" ]; then \
      EMBEDDING_BACKEND=sentence-transformers python -c "from tools.attack_mapper import get_backend; print(get_backend().name)"; \
    fi
ENV EMBEDDING_BACKEND=auto

RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
