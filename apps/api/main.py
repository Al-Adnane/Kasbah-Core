from fastapi import FastAPI

app = FastAPI(title="Kasbah Core")

@app.get("/")
def root():
    return {
        "name": "Kasbah Core",
        "tagline": "The Fortress for AI Agents",
        "status": "running"
    }

@app.get("/health")
def health():
    return {"ok": True}


