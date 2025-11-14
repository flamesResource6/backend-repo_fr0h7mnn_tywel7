"""
Database Schemas for LogiTrack

Each Pydantic model corresponds to a MongoDB collection (collection name is the lowercase of the class name).
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

Role = Literal["admin", "manager", "driver", "staff"]

class User(BaseModel):
    name: str
    email: EmailStr
    password: Optional[str] = None
    role: Role = "staff"
    assignedShipments: List[str] = []

class Checkpoint(BaseModel):
    location: str
    timestamp: datetime
    note: Optional[str] = None

ShipmentStatus = Literal["created", "picked", "in_transit", "delivered", "delayed", "cancelled"]

class Shipment(BaseModel):
    trackingId: str
    origin: str
    destination: str
    customer: str
    status: ShipmentStatus = "created"
    driverId: Optional[str] = None
    vehicleId: Optional[str] = None
    ETA: Optional[str] = None
    checkpoints: List[Checkpoint] = []

class Driver(BaseModel):
    name: str
    phone: str
    license: str
    availability: bool = True
    assignedVehicle: Optional[str] = None
    assignedShipments: List[str] = []

class Vehicle(BaseModel):
    numberPlate: str
    type: str
    status: Literal["idle", "on_road", "maintenance"] = "idle"
    capacity: Optional[int] = None
    currentLocation: Optional[dict] = None  # {lat, lng}

class Inventory(BaseModel):
    itemName: str
    quantity: int
    warehouseId: str

class Warehouse(BaseModel):
    name: str
    address: str
    stock: List[Inventory] = []
    capacity: Optional[int] = None
