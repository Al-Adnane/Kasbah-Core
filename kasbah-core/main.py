from fastapi import FastAPI

app = FastAPI(title="Kasbah Core", version="0.3.0")

@app.get("/")
def root():
    return {"name": "Kasbah Core", "status": "running", "version": app.version}

@app.get("/health")
def health():
    return {"ok": True}
