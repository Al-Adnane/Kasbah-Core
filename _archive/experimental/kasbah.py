from fastapi import FastAPI
import time
app = FastAPI()
@app.get("/health")
def health():
    return {"status": "ok", "time": time.time()}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
