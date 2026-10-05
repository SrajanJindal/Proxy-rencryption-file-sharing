from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from umbral import pre, Capsule, VerifiedKeyFrag

app = FastAPI()

storage = {
    "capsules": {},
    "kfrags": {}
}

class StoreCapsuleRequest(BaseModel):
    file_id: str
    capsule_bytes: str  

class StoreKFragRequest(BaseModel):
    file_id: str
    recipient_id: str
    kfrag_bytes: str  

@app.post("/upload_capsule")
def upload_capsule(req: StoreCapsuleRequest):
    storage["capsules"][req.file_id] = bytes.fromhex(req.capsule_bytes)
    return {"status": "Capsule stored successfully"}

@app.post("/grant_access")
def grant_access(req: StoreKFragRequest):
    storage["kfrags"][f"{req.file_id}_{req.recipient_id}"] = bytes.fromhex(req.kfrag_bytes)
    return {"status": "Access delegated via kfrag"}

@app.get("/reencrypt/{file_id}/{recipient_id}")
def get_reencrypted_cfrag(file_id: str, recipient_id: str):
    capsule_bytes = storage["capsules"].get(file_id)
    kfrag_bytes = storage["kfrags"].get(f"{file_id}_{recipient_id}")
    
    if not capsule_bytes or not kfrag_bytes:
        raise HTTPException(status_code=404, detail="Data not found")

    capsule = Capsule.from_bytes(capsule_bytes)
    kfrag = VerifiedKeyFrag.from_verified_bytes(kfrag_bytes)

    cfrag = pre.reencrypt(capsule=capsule, kfrag=kfrag)

    # Returning using bytes(cfrag)
    return {"cfrag_bytes": bytes(cfrag).hex()}
