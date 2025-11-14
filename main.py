import os
import random
import asyncio
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone

from database import db, create_document, get_documents
from schemas import User as UserSchema, Shipment as ShipmentSchema, Driver as DriverSchema, Vehicle as VehicleSchema, Warehouse as WarehouseSchema, Inventory as InventorySchema

# Environment
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

# Auth utils
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# FastAPI app
app = FastAPI(title="LogiTrack API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Helpers
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db["user"].find_one({"email": email})
    if not user:
        raise credentials_exception
    user["_id"] = str(user["_id"])  # convert for JSON
    return user


# Root
@app.get("/")
def read_root():
    return {"message": "LogiTrack Backend Running"}


# Auth routes
@app.post("/auth/signup", response_model=Token)
def signup(user: UserSchema):
    if db["user"].find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(user.password or "changeme")
    user_dict = user.model_dump()
    user_dict["password"] = hashed
    user_dict["created_at"] = datetime.utcnow()
    db["user"].insert_one(user_dict)
    token = create_access_token({"sub": user.email})
    return Token(access_token=token)


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db["user"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("password", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token({"sub": user["email"]})
    return Token(access_token=token)


@app.get("/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    current_user.pop("password", None)
    return current_user


# Shipments
@app.get("/shipments")
def list_shipments():
    items = get_documents("shipment")
    for x in items:
        x["_id"] = str(x["_id"])  # serialize
    return items


@app.post("/shipments")
def create_shipment(payload: ShipmentSchema):
    _id = create_document("shipment", payload)
    return {"_id": _id}


@app.get("/shipments/{sid}")
def get_shipment(sid: str):
    from bson import ObjectId
    doc = db["shipment"].find_one({"_id": ObjectId(sid)})
    if not doc:
        raise HTTPException(404, "Shipment not found")
    doc["_id"] = str(doc["_id"])  # serialize
    return doc


@app.put("/shipments/{sid}")
def update_shipment(sid: str, payload: ShipmentSchema):
    from bson import ObjectId
    res = db["shipment"].update_one({"_id": ObjectId(sid)}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(404, "Shipment not found")
    return {"updated": True}


@app.delete("/shipments/{sid}")
def delete_shipment(sid: str):
    from bson import ObjectId
    res = db["shipment"].delete_one({"_id": ObjectId(sid)})
    return {"deleted": res.deleted_count > 0}


class StatusPatch(BaseModel):
    status: str


@app.patch("/shipments/{sid}/status")
def patch_shipment_status(sid: str, body: StatusPatch):
    from bson import ObjectId
    res = db["shipment"].update_one({"_id": ObjectId(sid)}, {"$set": {"status": body.status, "updated_at": datetime.utcnow()}})
    if res.matched_count == 0:
        raise HTTPException(404, "Shipment not found")
    return {"updated": True}


# Drivers
@app.get("/drivers")
def list_drivers():
    items = get_documents("driver")
    for x in items:
        x["_id"] = str(x["_id"])  # serialize
    return items


@app.post("/drivers")
def create_driver(payload: DriverSchema):
    _id = create_document("driver", payload)
    return {"_id": _id}


@app.put("/drivers/{did}")
def update_driver(did: str, payload: DriverSchema):
    from bson import ObjectId
    res = db["driver"].update_one({"_id": ObjectId(did)}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(404, "Driver not found")
    return {"updated": True}


class AssignPatch(BaseModel):
    shipmentId: Optional[str] = None


@app.patch("/drivers/{did}/assign")
def assign_driver(did: str, body: AssignPatch):
    from bson import ObjectId
    update = {}
    if body.shipmentId:
        update = {"$addToSet": {"assignedShipments": body.shipmentId}}
    res = db["driver"].update_one({"_id": ObjectId(did)}, update)
    if res.matched_count == 0:
        raise HTTPException(404, "Driver not found")
    return {"updated": True}


@app.get("/drivers/available")
def available_drivers():
    drivers = list(db["driver"].find({"availability": True}))
    for d in drivers:
        d["_id"] = str(d["_id"])  # serialize
    return drivers


# Vehicles
@app.get("/vehicles")
def list_vehicles():
    items = get_documents("vehicle")
    for x in items:
        x["_id"] = str(x["_id"])  # serialize
    return items


@app.post("/vehicles")
def create_vehicle(payload: VehicleSchema):
    _id = create_document("vehicle", payload)
    return {"_id": _id}


@app.put("/vehicles/{vid}")
def update_vehicle(vid: str, payload: VehicleSchema):
    from bson import ObjectId
    res = db["vehicle"].update_one({"_id": ObjectId(vid)}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(404, "Vehicle not found")
    return {"updated": True}


# Warehouses + Inventory
@app.get("/warehouses")
def list_warehouses():
    items = get_documents("warehouse")
    for x in items:
        x["_id"] = str(x["_id"])  # serialize
    return items


@app.post("/warehouses")
def create_warehouse(payload: WarehouseSchema):
    _id = create_document("warehouse", payload)
    return {"_id": _id}


@app.put("/warehouses/{wid}")
def update_warehouse(wid: str, payload: WarehouseSchema):
    from bson import ObjectId
    res = db["warehouse"].update_one({"_id": ObjectId(wid)}, {"$set": payload.model_dump()})
    if res.matched_count == 0:
        raise HTTPException(404, "Warehouse not found")
    return {"updated": True}


@app.get("/warehouses/{wid}/inventory")
def get_inventory(wid: str):
    items = list(db["inventory"].find({"warehouseId": wid}))
    for x in items:
        x["_id"] = str(x["_id"])  # serialize
    return items


@app.post("/warehouses/{wid}/inventory")
def add_inventory(wid: str, payload: InventorySchema):
    data = payload.model_dump()
    data["warehouseId"] = wid
    data["created_at"] = datetime.now(timezone.utc)
    data["updated_at"] = datetime.now(timezone.utc)
    res = db["inventory"].insert_one(data)
    return {"_id": str(res.inserted_id)}


# Analytics (simple aggregations)
@app.get("/analytics/shipments")
def analytics_shipments():
    total = db["shipment"].count_documents({})
    by_status = list(db["shipment"].aggregate([
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]))
    return {"total": total, "byStatus": by_status}


@app.get("/analytics/fleet")
def analytics_fleet():
    total = db["vehicle"].count_documents({})
    by_status = list(db["vehicle"].aggregate([
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]))
    return {"total": total, "byStatus": by_status}


@app.get("/analytics/warehouse")
def analytics_warehouse():
    total = db["warehouse"].count_documents({})
    inv = db["inventory"].aggregate([
        {"$group": {"_id": None, "sumQty": {"$sum": "$quantity"}}}
    ])
    total_qty = 0
    for x in inv:
        total_qty = x.get("sumQty", 0)
    return {"totalWarehouses": total, "totalInventoryQty": total_qty}


@app.get("/analytics/deliveries")
def analytics_deliveries():
    trend = list(db["shipment"].aggregate([
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]))
    return {"trend": trend}


# Seeder (dev-only)
@app.post("/seed")
def seed_data():
    from random import randint, choice, uniform
    # Avoid reseeding if already populated
    if db["driver"].count_documents({}) >= 10:
        return {"seeded": False, "message": "Already seeded"}

    # Users
    db["user"].insert_many([
        {"name": "Admin", "email": "admin@logitrack.io", "password": get_password_hash("admin"), "role": "admin", "created_at": datetime.utcnow()},
        {"name": "Manager", "email": "manager@logitrack.io", "password": get_password_hash("manager"), "role": "manager", "created_at": datetime.utcnow()},
    ])

    # Drivers
    drivers = []
    for i in range(10):
        drivers.append({
            "name": f"Driver {i+1}",
            "phone": f"+1-555-000{i}",
            "license": f"LIC-{1000+i}",
            "availability": True,
            "assignedVehicle": None,
            "assignedShipments": []
        })
    db["driver"].insert_many(drivers)

    # Vehicles
    vehicles = []
    types = ["truck", "van", "bike"]
    for i in range(10):
        vehicles.append({
            "numberPlate": f"LT-{1000+i}",
            "type": choice(types),
            "status": choice(["idle", "on_road", "maintenance"]),
            "capacity": randint(500, 5000),
            "currentLocation": {"lat": 37.77 + uniform(-0.2, 0.2), "lng": -122.41 + uniform(-0.2, 0.2)}
        })
    db["vehicle"].insert_many(vehicles)

    # Warehouses
    warehouses = []
    for i in range(5):
        warehouses.append({
            "name": f"Warehouse {i+1}",
            "address": f"{100+i} Market St, City",
            "stock": [],
            "capacity": randint(1000, 10000)
        })
    db["warehouse"].insert_many(warehouses)

    # Inventory
    inv = []
    for i in range(50):
        inv.append({
            "itemName": f"Item {i+1}",
            "quantity": randint(1, 200),
            "warehouseId": str(choice(list(db["warehouse"].find({}, {"_id": 1})))['_id'])
        })
    db["inventory"].insert_many(inv)

    # Shipments
    statuses = ["created", "picked", "in_transit", "delivered", "delayed"]
    shipments = []
    for i in range(20):
        shipments.append({
            "trackingId": f"TRK-{10000+i}",
            "origin": "San Francisco, CA",
            "destination": "Los Angeles, CA",
            "customer": f"Customer {i+1}",
            "status": choice(statuses),
            "driverId": None,
            "vehicleId": None,
            "ETA": "2025-12-31",
            "checkpoints": []
        })
    db["shipment"].insert_many(shipments)

    return {"seeded": True}


# Live updates via WebSocket (mock stream)
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active:
            self.active.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Generate mock vehicle updates
            vehicles = list(db["vehicle"].find({}).limit(10))
            updates = []
            for v in vehicles:
                loc = v.get("currentLocation") or {"lat": 37.77, "lng": -122.41}
                # random walk
                loc["lat"] += random.uniform(-0.002, 0.002)
                loc["lng"] += random.uniform(-0.002, 0.002)
                db["vehicle"].update_one({"_id": v["_id"]}, {"$set": {"currentLocation": loc}})
                updates.append({"vehicleId": str(v["_id"]), "location": loc})
            await manager.broadcast({"type": "vehicle_updates", "data": updates, "ts": datetime.utcnow().isoformat()})
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# Database diagnostics
@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = os.getenv("DATABASE_NAME") or "❌ Not Set"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
            response["connection_status"] = "Connected"
    except Exception as e:
        response["database"] = f"⚠️  Error: {str(e)[:80]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
