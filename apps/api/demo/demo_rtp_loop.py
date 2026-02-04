import json, urllib.request
base="http://127.0.0.1:8001"
def post(path,data):
    req=urllib.request.Request(base+path,data=json.dumps(data).encode(),headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())

dec=post("/api/rtp/decide",{"tool":"shell.exec","args":{"command":"echo hi"},"system_stable":True,"limits":{"maxTokens":2000,"maxCostCents":500}})
print("DECIDE:",json.dumps(dec,indent=2))
jti=dec["ticket"]["jti"]
c1=post("/api/rtp/consume",{"tool":"shell.exec","jti":jti,"usage":{"tokens":1,"cost":0}})
print("\nCONSUME 1:",json.dumps(c1,indent=2))
c2=post("/api/rtp/consume",{"tool":"shell.exec","jti":jti,"usage":{"tokens":1,"cost":0}})
print("\nCONSUME 2 (replay):",json.dumps(c2,indent=2))
