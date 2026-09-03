# ========== ИМПОРТЫ ==========
import os
import logging
from typing import List, Optional
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
import pytz

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base

from pydantic import BaseModel, EmailStr, Field, ConfigDict

from jose import JWTError, jwt

# ✅ ИСПОЛЬЗУЕМ BCrypt НАПРЯМУЮ (без passlib!)
import bcrypt

# ========== НАСТРОЙКА ЛОГИРОВАНИЯ ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ========== ЗАГРУЗКА .env ==========
load_dotenv()

# ========== НАСТРОЙКИ ==========
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY not set in .env file!")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ========== FASTAPI APP ==========
app = FastAPI(
    title="Habit Tracker API",
    description="API for tracking daily habits with streaks",
    version="1.0.0"
)

# ========== CORS ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== БАЗА ДАННЫХ ==========
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./habits.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ========== БЕЗОПАСНОСТЬ ==========
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ========== ФУНКЦИИ ХЭШИРОВАНИЯ (BCrypt - БЕЗ PASSLIB) ==========
def get_password_hash(password: str) -> str:
    """Хэширует пароль с использованием bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет пароль"""
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )

# ========== МОДЕЛИ БАЗЫ ДАННЫХ ==========
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    email = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(pytz.UTC))
    avatar_color = Column(String(7), default="#667eea")
    
    habits = relationship("Habit", back_populates="owner", cascade="all, delete-orphan")

class Habit(Base):
    __tablename__ = "habits"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), index=True, nullable=False)
    description = Column(String(500), default="")
    completed = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(pytz.UTC))
    current_streak = Column(Integer, default=0)
    longest_streak = Column(Integer, default=0)
    last_completed_date = Column(DateTime, nullable=True)
    
    owner = relationship("User", back_populates="habits")

# ========== СОЗДАНИЕ ТАБЛИЦ ==========
Base.metadata.create_all(bind=engine)

# ========== PYDANTIC СХЕМЫ ==========
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    email: Optional[EmailStr] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    created_at: datetime
    avatar_color: str = "#667eea"
    
    model_config = ConfigDict(from_attributes=True)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    avatar_color: Optional[str] = Field(None, pattern=r'^#[0-9a-fA-F]{6}$')

class PasswordChange(BaseModel):
    old_password: str = Field(..., min_length=6)
    new_password: str = Field(..., min_length=6)

class HabitCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)

class HabitUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)

class HabitResponse(BaseModel):
    id: int
    title: str
    description: str = ""
    completed: bool
    current_streak: int = 0
    longest_streak: int = 0
    last_completed_date: Optional[datetime] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(pytz.UTC) + expires_delta
    else:
        expire = datetime.now(pytz.UTC) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
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
    user = get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# ========== ROOT ENDPOINT ==========
@app.get("/", tags=["Root"])
def root():
    return {
        "message": "Habit Tracker API",
        "docs": "/docs",
        "health": "/health"
    }

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(pytz.UTC).isoformat()
    }

# ========== АУТЕНТИФИКАЦИЯ ==========
@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, tags=["Auth"])
def register(user: UserCreate, db: Session = Depends(get_db)):
    logger.info(f"Registration attempt for username: {user.username}")
    
    db_user = get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        hashed_password=hashed_password,
        email=user.email
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    logger.info(f"User registered successfully: {user.username}")
    return new_user

@app.post("/token", response_model=Token, tags=["Auth"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    logger.info(f"Login attempt for username: {form_data.username}")
    
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    logger.info(f"User logged in successfully: {form_data.username}")
    return {"access_token": access_token, "token_type": "bearer"}

# ========== ПРОФИЛЬ ==========
@app.get("/profile", response_model=UserResponse, tags=["Profile"])
def get_profile(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/profile", response_model=UserResponse, tags=["Profile"])
def update_profile(
    profile: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if profile.email is not None:
        current_user.email = profile.email
    if profile.avatar_color is not None:
        current_user.avatar_color = profile.avatar_color
    
    db.commit()
    db.refresh(current_user)
    return current_user

@app.post("/change-password", tags=["Profile"])
def change_password(
    data: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password is incorrect")
    
    current_user.hashed_password = get_password_hash(data.new_password)
    db.commit()
    return {"message": "Password changed successfully"}

@app.delete("/delete-account", tags=["Profile"])
def delete_account(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    logger.warning(f"User {current_user.username} is deleting account")
    db.delete(current_user)
    db.commit()
    return {"message": "Account deleted successfully"}

# ========== ПРИВЫЧКИ ==========
@app.post("/habits", response_model=HabitResponse, status_code=status.HTTP_201_CREATED, tags=["Habits"])
def create_habit(
    habit: HabitCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    logger.info(f"User {current_user.username} creating habit: {habit.title}")
    
    new_habit = Habit(
        title=habit.title,
        description=habit.description or "",
        user_id=current_user.id
    )
    db.add(new_habit)
    db.commit()
    db.refresh(new_habit)
    
    return new_habit

@app.get("/habits", response_model=List[HabitResponse], tags=["Habits"])
def get_habits(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    habits = db.query(Habit).filter(Habit.user_id == current_user.id).all()
    return habits

@app.get("/habits/{habit_id}", response_model=HabitResponse, tags=["Habits"])
def get_habit(
    habit_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    habit = db.query(Habit).filter(Habit.id == habit_id, Habit.user_id == current_user.id).first()
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    return habit

@app.put("/habits/{habit_id}", response_model=HabitResponse, tags=["Habits"])
def update_habit(
    habit_id: int,
    habit_data: HabitUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    habit = db.query(Habit).filter(Habit.id == habit_id, Habit.user_id == current_user.id).first()
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    if habit_data.title is not None:
        habit.title = habit_data.title
    if habit_data.description is not None:
        habit.description = habit_data.description
    
    db.commit()
    db.refresh(habit)
    return habit

@app.put("/habits/{habit_id}/complete", response_model=HabitResponse, tags=["Habits"])
def complete_habit(
    habit_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    habit = db.query(Habit).filter(Habit.id == habit_id, Habit.user_id == current_user.id).first()
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    now = datetime.now(pytz.UTC)
    today = now.date()
    
    # Если уже выполнена сегодня - снимаем выполнение
    if habit.last_completed_date and habit.last_completed_date.date() == today and habit.completed:
        habit.completed = False
        if habit.current_streak > 0:
            habit.current_streak -= 1
        db.commit()
        db.refresh(habit)
        return habit
    
    # Если не выполнена - выполняем
    habit.completed = True
    
    if habit.last_completed_date:
        last_date = habit.last_completed_date.date()
        yesterday = today - timedelta(days=1)
        
        if last_date == yesterday:
            habit.current_streak += 1
        elif last_date < yesterday:
            habit.current_streak = 1
    else:
        habit.current_streak = 1
    
    if habit.current_streak > habit.longest_streak:
        habit.longest_streak = habit.current_streak
    
    habit.last_completed_date = now
    db.commit()
    db.refresh(habit)
    
    logger.info(f"User {current_user.username} completed habit: {habit.title} (streak: {habit.current_streak})")
    return habit

@app.delete("/habits/{habit_id}", tags=["Habits"])
def delete_habit(
    habit_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    habit = db.query(Habit).filter(Habit.id == habit_id, Habit.user_id == current_user.id).first()
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    logger.info(f"User {current_user.username} deleting habit: {habit.title}")
    db.delete(habit)
    db.commit()
    return {"message": "Habit deleted successfully"}



