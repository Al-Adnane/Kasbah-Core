import json, sys
d = json.load(sys.stdin)
expr = sys.argv[1]
ctx = {"d": d}
ok = eval(expr, {}, ctx)
if not ok:
    print("ASSERT_FAIL:", expr)
    print(json.dumps(d, indent=2)[:2000])
    raise SystemExit(1)
print("ASSERT_OK:", expr)
