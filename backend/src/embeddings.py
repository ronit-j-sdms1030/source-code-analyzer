"""HuggingFace sentence-transformers embedding wrapper."""

from functools import lru_cache

from . import config


@lru_cache(maxsize=1)
def _get_model():
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(config.EMBEDDING_MODEL)


def embed_chunks(texts: list) -> list:
    """Converts a list of code chunk strings into vector embeddings (batched)."""
    if not texts:
        return []
    model = _get_model()
    return model.encode(texts, batch_size=32, show_progress_bar=False).tolist()


def embed_query(text: str) -> list:
    return embed_chunks([text])[0]
