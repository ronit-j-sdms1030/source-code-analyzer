import os
# We no longer need TOKENIZERS_PARALLELISM hack because we aren't using PyTorch/sentence-transformers
from functools import lru_cache
from . import config

@lru_cache(maxsize=1)
def _get_model():
    from fastembed import TextEmbedding
    # Use exact same model weights to maintain compatibility with existing ChromaDB vectors
    model_name = config.EMBEDDING_MODEL
    if not model_name.startswith("sentence-transformers/"):
        model_name = f"sentence-transformers/{model_name}"
        
    return TextEmbedding(model_name=model_name, threads=None)

def embed_chunks(texts: list, progress_callback=None) -> list:
    """Converts a list of code chunk strings into vector embeddings using fastembed."""
    if not texts:
        return []
    
    # FastEmbed uses ONNX Runtime which is thread-safe for inference,
    # so we no longer need _embed_lock here. This allows concurrent indexing!
    model = _get_model()
    
    # FastEmbed returns a generator of numpy arrays. We convert them to lists of floats for ChromaDB.
    embeddings_generator = model.embed(texts)
    
    results = []
    total = len(texts)
    for i, embedding in enumerate(embeddings_generator):
        results.append(embedding.tolist())
        if progress_callback:
            progress_callback(i + 1, total)
            
    return results

def embed_query(text: str) -> list:
    return embed_chunks([text])[0]
