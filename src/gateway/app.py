from fastapi import FastAPI, Depends, Header, HTTPException
from starlette.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import RequestLog
from .middleware import WAFMiddleware
from .config import DEMO_API_KEYS

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ADL-WAF (IsolationForest + SVM) Gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(WAFMiddleware)

def verify_api_key(x_api_key: str = Header(default=None)):
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="Missing X-API-Key")
    if x_api_key not in DEMO_API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key

@app.get("/")
async def root():
    return {
        "message": "Gateway running",
        "endpoints": ["/public", "/secure-data", "/submit", "/admin/logs"]
    }

@app.get("/public")
async def public():
    return {"message": "Public endpoint"}

@app.get("/secure-data")
async def secure_data(api_key: str = Depends(verify_api_key)):
    return {"message": "Secure data", "api_key": api_key}

@app.post("/submit")
async def submit(data: dict):
    return {"received": data}

@app.get("/admin/logs")
def admin_logs(limit: int = 50, db: Session = Depends(get_db)):
    logs = db.query(RequestLog).order_by(RequestLog.id.desc()).limit(limit).all()
    return [
        {
            "id": x.id,
            "time": x.created_at,
            "ip": x.client_ip,
            "path": x.path,
            "l1_anomaly": x.l1_anomaly,
            "anomaly_score": x.anomaly_score,
            "l2_type": x.l2_type,
            "blocked": x.is_blocked,
            "reason": x.block_reason,
        }
        for x in logs
    ]
