import os
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from umbral import pre, Capsule, VerifiedKeyFrag
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker, Session, declarative_base

# --- DATABASE SETUP ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:proxy_admin_pass@db:5432/pre_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class DBCapsule(Base):
    __tablename__ = "capsules"
    file_id = Column(String, primary_key=True, index=True)
    capsule_hex = Column(String, nullable=False)

class DBKFrag(Base):
    __tablename__ = "kfrags"
    id = Column(String, primary_key=True) 
    file_id = Column(String, index=True)
    recipient_id = Column(String, index=True)
    kfrag_hex = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- API MODELS ---
class StoreCapsuleRequest(BaseModel):
    file_id: str
    capsule_bytes: str

class StoreKFragRequest(BaseModel):
    file_id: str
    recipient_id: str
    kfrag_bytes: str

# --- ENDPOINTS ---
@app.post("/upload_capsule")
def upload_capsule(req: StoreCapsuleRequest, db: Session = Depends(get_db)):
    db_capsule = db.query(DBCapsule).filter(DBCapsule.file_id == req.file_id).first()
    if db_capsule:
        db_capsule.capsule_hex = req.capsule_bytes
    else:
        db_capsule = DBCapsule(file_id=req.file_id, capsule_hex=req.capsule_bytes)
        db.add(db_capsule)
    db.commit()
    return {"status": "Capsule stored permanently in PostgreSQL"}

@app.post("/grant_access")
def grant_access(req: StoreKFragRequest, db: Session = Depends(get_db)):
    kfrag_id = f"{req.file_id}_{req.recipient_id}"
    db_kfrag = db.query(DBKFrag).filter(DBKFrag.id == kfrag_id).first()
    if db_kfrag:
        db_kfrag.kfrag_hex = req.kfrag_bytes
    else:
        db_kfrag = DBKFrag(
            id=kfrag_id, file_id=req.file_id, 
            recipient_id=req.recipient_id, kfrag_hex=req.kfrag_bytes
        )
        db.add(db_kfrag)
    db.commit()
    return {"status": "Access delegated via kfrag in PostgreSQL"}

@app.delete("/revoke_access/{file_id}/{recipient_id}")
def revoke_access(file_id: str, recipient_id: str, db: Session = Depends(get_db)):
    kfrag_id = f"{file_id}_{recipient_id}"
    db_kfrag = db.query(DBKFrag).filter(DBKFrag.id == kfrag_id).first()
    if not db_kfrag:
        raise HTTPException(status_code=404, detail="Access delegation not found or already revoked")
    
    db.delete(db_kfrag)
    db.commit()
    return {"status": f"Access successfully revoked for {recipient_id}"}

@app.get("/reencrypt/{file_id}/{recipient_id}")
def get_reencrypted_cfrag(file_id: str, recipient_id: str, db: Session = Depends(get_db)):
    db_capsule = db.query(DBCapsule).filter(DBCapsule.file_id == file_id).first()
    db_kfrag = db.query(DBKFrag).filter(DBKFrag.id == f"{file_id}_{recipient_id}").first()
    
    if not db_capsule or not db_kfrag:
        raise HTTPException(status_code=404, detail="Access denied: KFrag or Capsule not found")

    capsule = Capsule.from_bytes(bytes.fromhex(db_capsule.capsule_hex))
    kfrag = VerifiedKeyFrag.from_verified_bytes(bytes.fromhex(db_kfrag.kfrag_hex))

    cfrag = pre.reencrypt(capsule=capsule, kfrag=kfrag)

    return {"cfrag_bytes": bytes(cfrag).hex()}
