#!/usr/bin/env python3
"""
Head-to-head benchmark on the public deepset/prompt-injections TEST split (116
held-out cases). Reports the Kasbah embedding classifier's precision/recall/F1/
accuracy and gates against a checked-in floor. Exits non-zero on regression.

This is the "detection coverage depth" moat, measured on PUBLIC data — not a
homemade corpus. The number here is directly comparable to what vendors in this
category (Lakera Guard, ProtectAI LLM Guard, deepset's own model) report on the
same dataset.

Usage:
    python3 bench/injection-classifier/benchmark.py [--data-dir /tmp]
"""
import json, os, sys, argparse, urllib.request

# Regression floor — measured 2026-07-07 on this exact test split.
# The previous regex/RTP /v1/govern path scored acc=0.491 (chance) for reference.
FLOOR = {'f1': 0.80, 'accuracy': 0.80}


def fetch_test(data_dir):
    if data_dir and os.path.exists(os.path.join(data_dir, 'deepset_test.json')):
        return json.load(open(os.path.join(data_dir, 'deepset_test.json')))
    def page(off, length):
        url = ('https://datasets-server.huggingface.co/rows?dataset=deepset%2F'
               f'prompt-injections&config=default&split=test&offset={off}&length={length}')
        req = urllib.request.Request(url, headers={'User-Agent': 'kasbah-bench'})
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data-dir', default=None)
    ap.add_argument('--threshold', type=float, default=None)
    args = ap.parse_args()

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..',
                                    'packages', 'api-server', 'src', 'ml'))
    from injection_classifier import Classifier

    test = fetch_test(args.data_dir)
    clf = Classifier()
    thr = args.threshold if args.threshold is not None else clf.w['default_threshold']

    tp = fp = tn = fn = 0
    for r in test:
        inj = clf.score(r['text']) >= thr
        truth = r['label'] == 1
        if inj and truth: tp += 1
        elif inj and not truth: fp += 1
        elif not inj and truth: fn += 1
        else: tn += 1

    P = tp/(tp+fp) if tp+fp else 0.0
    R = tp/(tp+fn) if tp+fn else 0.0
    F = 2*P*R/(P+R) if P+R else 0.0
    A = (tp+tn)/len(test)

    print(f'=== Kasbah injection classifier vs deepset/prompt-injections TEST (n={len(test)}, thr={thr}) ===')
    print(f'precision={P:.3f} recall={R:.3f} F1={F:.3f} accuracy={A:.3f}  (TP{tp} FP{fp} TN{tn} FN{fn})')
    print(f'baseline (old regex/RTP /v1/govern): F1=0.599 accuracy=0.491 (chance)')
    print(f'floor: F1>={FLOOR["f1"]} accuracy>={FLOOR["accuracy"]}')

    if F < FLOOR['f1'] or A < FLOOR['accuracy']:
        print('REGRESSION: below floor', file=sys.stderr)
        sys.exit(1)
    print('PASS')


if __name__ == '__main__':
    main()
