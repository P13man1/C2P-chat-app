# backend.py - Complete working backend

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, WebSocket, WebSocketDisconnect, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timedelta
from jose import JWTError, jwt
import bcrypt
from typing import Optional, List
import uuid
from pathlib import Path
import uvicorn
import secrets
import os
import shutil
import json

# ==================== CONFIGURATION ====================
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "sqlite:///./chat_app.db"
UPLOAD_DIR = "uploads"

# Create upload directory
Path(UPLOAD_DIR).mkdir(exist_ok=True)

# ==================== DATABASE SETUP ====================
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(200))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Group(Base):
    __tablename__ = "groups"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100))
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class GroupMember(Base):
    __tablename__ = "group_members"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    group_id = Column(Integer, ForeignKey("groups.id"))
    joined_at = Column(DateTime, default=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    group_id = Column(Integer, ForeignKey("groups.id"))
    file_url = Column(String(500), nullable=True)
    file_type = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

# ==================== PASSWORD HASHING ====================
def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt"""
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        password_bytes = plain_password.encode('utf-8')[:72]
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        return False

# ==================== AUTHENTICATION ====================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise credentials_exception
        return user
    finally:
        db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==================== WEBSOCKET MANAGER ====================
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, list] = {}

    async def connect(self, websocket: WebSocket, group_id: int, user_id: int):
        await websocket.accept()
        if group_id not in self.active_connections:
            self.active_connections[group_id] = []
        self.active_connections[group_id].append({
            "websocket": websocket,
            "user_id": user_id
        })
        print(f"User {user_id} connected to group {group_id}")

    def disconnect(self, websocket: WebSocket, group_id: int):
        if group_id in self.active_connections:
            self.active_connections[group_id] = [
                conn for conn in self.active_connections[group_id]
                if conn["websocket"] != websocket
            ]
            print(f"User disconnected from group {group_id}")

    async def broadcast_to_group(self, message: dict, group_id: int, sender_id: int = None):
        """Send message to all members of a group"""
        if group_id in self.active_connections:
            for connection in self.active_connections[group_id]:
                # Optionally skip sender
                if sender_id and connection["user_id"] == sender_id:
                    continue
                try:
                    await connection["websocket"].send_json(message)
                except Exception as e:
                    print(f"Error sending to user {connection['user_id']}: {e}")

manager = ConnectionManager()

# ==================== FASTAPI APP ====================
app = FastAPI(title="Chat App API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files for uploads
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

# ==================== API ENDPOINTS ====================
@app.get("/")
async def root():
    return {"message": "Chat App API is running", "status": "online"}

@app.post("/api/register")
async def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if user exists
    existing_user = db.query(User).filter(
        (User.username == username) | (User.email == email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Create new user
    hashed_password = get_password_hash(password)
    user = User(
        username=username,
        email=email,
        hashed_password=hashed_password
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {"message": "User created successfully", "user_id": user.id}

@app.post("/api/login")
async def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username
    }

@app.post("/api/groups")
async def create_group(
    name: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Create group
    group = Group(name=name, created_by=current_user.id)
    db.add(group)
    db.commit()
    db.refresh(group)
    
    # Add creator as member
    member = GroupMember(user_id=current_user.id, group_id=group.id)
    db.add(member)
    db.commit()
    
    return {
        "group_id": group.id, 
        "name": group.name,
        "message": f"Group created! Share this ID: {group.id}"
    }

@app.get("/api/groups")
async def get_user_groups(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    groups = db.query(Group).join(GroupMember).filter(
        GroupMember.user_id == current_user.id
    ).all()
    
    return [
        {"id": g.id, "name": g.name, "created_at": g.created_at.isoformat() if g.created_at else None}
        for g in groups
    ]

@app.post("/api/groups/{group_id}/join")
async def join_group(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if group exists
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    
    # Check if already a member
    existing = db.query(GroupMember).filter(
        GroupMember.user_id == current_user.id,
        GroupMember.group_id == group_id
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Already a member")
    
    # Add member
    member = GroupMember(user_id=current_user.id, group_id=group_id)
    db.add(member)
    db.commit()
    
    return {"message": f"Joined group '{group.name}' successfully"}

@app.get("/api/groups/{group_id}/members")
async def get_group_members(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify user is in group
    member = db.query(GroupMember).filter(
        GroupMember.user_id == current_user.id,
        GroupMember.group_id == group_id
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    members = db.query(User).join(GroupMember).filter(
        GroupMember.group_id == group_id
    ).all()
    
    return [
        {"id": m.id, "username": m.username}
        for m in members
    ]

@app.post("/api/groups/{group_id}/messages")
async def send_message(
    group_id: int,
    content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify user is in group
    member = db.query(GroupMember).filter(
        GroupMember.user_id == current_user.id,
        GroupMember.group_id == group_id
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    file_url = None
    file_type = None
    
    if file and file.filename:
        # Save file
        file_extension = file.filename.split(".")[-1] if file.filename else "bin"
        file_name = f"{uuid.uuid4()}.{file_extension}"
        file_path = Path(UPLOAD_DIR) / file_name
        
        # Read and save file
        content_bytes = await file.read()
        with open(file_path, "wb") as buffer:
            buffer.write(content_bytes)
        
        file_url = f"/uploads/{file_name}"
        file_type = file.content_type
    
    # Save message
    message = Message(
        content=content,
        sender_id=current_user.id,
        group_id=group_id,
        file_url=file_url,
        file_type=file_type
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    
    # Get sender info
    sender = db.query(User).filter(User.id == current_user.id).first()
    
    # Prepare message data
    message_data = {
        "type": "new_message",
        "id": message.id,
        "content": content,
        "sender_id": current_user.id,
        "sender_name": sender.username if sender else "Unknown",
        "file_url": file_url,
        "file_type": file_type,
        "created_at": datetime.utcnow().isoformat()
    }
    
    # Broadcast to all members in group (including sender for local update)
    await manager.broadcast_to_group(message_data, group_id)
    
    return message_data

@app.get("/api/groups/{group_id}/messages")
async def get_messages(
    group_id: int,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify user is in group
    member = db.query(GroupMember).filter(
        GroupMember.user_id == current_user.id,
        GroupMember.group_id == group_id
    ).first()
    
    if not member:
        raise HTTPException(status_code=403, detail="Not a member of this group")
    
    messages = db.query(Message).filter(
        Message.group_id == group_id
    ).order_by(Message.created_at.asc()).offset(offset).limit(limit).all()
    
    result = []
    for msg in messages:
        sender = db.query(User).filter(User.id == msg.sender_id).first()
        result.append({
            "id": msg.id,
            "content": msg.content,
            "sender_id": msg.sender_id,
            "sender_name": sender.username if sender else "Unknown",
            "file_url": msg.file_url,
            "file_type": msg.file_type,
            "created_at": msg.created_at.isoformat() if msg.created_at else None
        })
    
    return result

@app.websocket("/ws/{group_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    group_id: int,
    token: str
):
    db = SessionLocal()
    try:
        # Authenticate user
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            await websocket.close(code=1008)
            return
        
        user = db.query(User).filter(User.username == username).first()
        if not user:
            await websocket.close(code=1008)
            return
        
        # Verify user is in group
        member = db.query(GroupMember).filter(
            GroupMember.user_id == user.id,
            GroupMember.group_id == group_id
        ).first()
        
        if not member:
            await websocket.close(code=1008)
            return
        
        await manager.connect(websocket, group_id, user.id)
        
        try:
            while True:
                data = await websocket.receive_json()
                if data["type"] == "typing":
                    await manager.broadcast_to_group({
                        "type": "typing",
                        "user_id": user.id,
                        "username": user.username,
                        "group_id": group_id
                    }, group_id, user.id)  # Skip sender
                    
        except WebSocketDisconnect:
            manager.disconnect(websocket, group_id)
            
    except Exception as e:
        print(f"WebSocket error: {e}")
        await websocket.close(code=1011)
    finally:
        db.close()

# ==================== RUN SERVER ====================
if __name__ == "__main__":
    print("="*50)
    print("Chat App Backend Server")
    print("="*50)
    print(f"Server running on: http://localhost:8000")
    print(f"API Documentation: http://localhost:8000/docs")
    print("="*50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
