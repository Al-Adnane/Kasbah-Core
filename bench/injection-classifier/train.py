#!/usr/bin/env python3
"""
Train the Kasbah prompt-injection classifier.

Frozen sentence-transformers embedding (all-MiniLM-L6-v2) + logistic regression.
No novel math — a standard, boring, well-understood linear classifier on top of
public pretrained embeddings. The logreg weights are exported as plain JSON
(384 floats + intercept) so the model is fully auditable and diff-able in git;
there is no opaque binary blob and no pickle.

Training data: the deepset/prompt-injections TRAIN split only (546 rows). The
TEST split (116 rows) is NEVER seen here — it is held out purely for the
head-to-head benchmark in bench/injection-classifier/benchmark.py.

Usage:
    python3 bench/injection-classifier/train.py            # fetches data, trains, writes weights.json
    python3 bench/injection-classifier/train.py --data-dir /tmp   # reuse cached deepset_{train,test}.json

Output: packages/api-server/src/ml/injection-classifier.json
"""
import json, os, sys, urllib.request, argparse
import numpy as np

MODEL_NAME = 'sentence-transformers/all-MiniLM-L6-v2'
OUT = os.path.join(os.path.dirname(__file__), '..', '..',
                   'packages', 'api-server', 'src', 'ml', 'injection-classifier.json')


def fetch_split(split):
    def page(off, length):
        url = ('https://datasets-server.huggingface.co/rows?dataset=deepset%2F'
               f'prompt-injections&config=default&split={split}&offset={off}&length={length}')
        req = urllib.request.Request(url, headers={'User-Agent': 'kasbah-train'})
        return json.loads(urllib.request.urlopen(req, timeout=30).read())
    n = page(0, 1).get('num_rows_total', 0)
    rows, off = [], 0
    while off < n:
        r = page(off, 100).get('rows', [])
        if not r:
            break
        rows += r
        off += len(r)
    return [{'text': x['row']['text'], 'label': x['row']['label']} for x in rows]


def load(split, data_dir):
    if data_dir:
        p = os.path.join(data_dir, f'deepset_{split}.json')
        if os.path.exists(p):
            return json.load(open(p))
    return fetch_split(split)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data-dir', default=None)
    args = ap.parse_args()

    from sentence_transformers import SentenceTransformer
    from sklearn.linear_model import LogisticRegression

    train = load('train', args.data_dir)
    print(f'train rows: {len(train)}  (injection={sum(r["label"] for r in train)})')

    model = SentenceTransformer(MODEL_NAME)
    X = model.encode([r['text'] for r in train], normalize_embeddings=True, show_progress_bar=False)
    y = np.array([r['label'] for r in train])

    clf = LogisticRegression(max_iter=2000, class_weight='balanced', C=1.0)
    clf.fit(X, y)

    weights = {
        'schema': 'kasbah-injection-classifier/v1',
        'embedding_model': MODEL_NAME,
        'normalize_embeddings': True,
        'dim': int(X.shape[1]),
        'coef': clf.coef_[0].astype(float).tolist(),
        'intercept': float(clf.intercept_[0]),
        'default_threshold': 0.5,
        'trained_on': 'deepset/prompt-injections train split',
        'train_rows': len(train),
        'note': 'Sigmoid(coef . normalize(embed(text)) + intercept) >= threshold => injection. '
                'Boring linear classifier on frozen public embeddings; no novel math.',
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(weights, open(OUT, 'w'), indent=2)
    print(f'wrote {OUT}  ({len(weights["coef"])} coefficients)')


if __name__ == '__main__':
    main()
