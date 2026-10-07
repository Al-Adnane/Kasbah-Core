"""injection_classifier.py — Python side of the frozen-embedding classifier.

Mirrors packages/api-server/src/ml/injection-js.js exactly:
  sigmoid(coef . normalize(embed(text)) + intercept) >= threshold.

Weights come from bench/injection-classifier/../.. (the JSON exported by
train.py). Embeddings need sentence-transformers (pip install
sentence-transformers); without it the constructor raises an actionable
error instead of a bare ModuleNotFoundError traceback.
"""
import json
import math
import os

_JSON = os.path.join(os.path.dirname(__file__), '..', '..',
                     'packages', 'api-server', 'src', 'ml',
                     'injection-classifier.json')


def _sigmoid(x):
    return 1.0 / (1.0 + math.exp(-x))


class Classifier:
    def __init__(self, weights_path=None):
        with open(weights_path or _JSON) as f:
            blob = json.load(f)
        self.coef = blob['coef']
        self.intercept = blob.get('intercept', 0.0)
        self.w = {'default_threshold': blob.get('threshold', 0.5)}
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise RuntimeError(
                'sentence-transformers is required for the Python benchmark '
                '(pip install sentence-transformers). The JS parity path '
                '(benchmark-js.js) needs no Python deps.'
            ) from e
        self._model = SentenceTransformer(
            blob.get('embedding_model', 'sentence-transformers/all-MiniLM-L6-v2'))

    def embed(self, text):
        vec = self._model.encode([text], normalize_embeddings=True)[0]
        return [float(x) for x in vec]

    def score(self, text):
        vec = self.embed(text)
        return _sigmoid(sum(c * v for c, v in zip(self.coef, vec)) + self.intercept)
