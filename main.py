# ========== ИМПОРТЫ ==========
from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime  # ✅ Добавили DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, ConfigDict  # ✅ Добавили ConfigDict
from typing import List, Optional
from datetime import datetime, timedelta, date  # ✅ Только один раз
from jose import JWTError, jwt  # ✅ Правильный импорт (jose, а не jwt)
import bcrypt
import os  # ✅ Для работы с .env
from dotenv import load_dotenv  # ✅ Для .env
import pytz  # ✅ Для работы с часовыми поясами

# ========== ЗАГРУЗКА .env ==========
load_dotenv()

# ========== НАСТРОЙКИ ==========
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY not set in .env file!")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

# ========== БАЗА ДАННЫХ ==========
DATABASE_URL = "sqlite:///./habits.db"  # ✅ Исправлен путь
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ========== JWT ==========
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ========== ФУНКЦИИ ХЭШИРОВАНИЯ ==========
def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# ========== МОДЕЛИ БАЗЫ ДАННЫХ ==========
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    email = Column(String, nullable=True)
    created_at = Column(String, default="")
    avatar_color = Column(String, default="#667eea")
    habits = relationship("Habit", back_populates="owner")

class Habit(Base):
    __tablename__ = "habits"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, default="")
    completed = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="habits")
    current_streak = Column(Integer, default=0)
    longest_streak = Column(Integer, default=0)
    last_completed_date = Column(DateTime, nullable=True)  # ✅ ИСПРАВЛЕНО!

# ========== СХЕМЫ PYDANTIC ==========
class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = ""
    created_at: str = ""
    avatar_color: str = "#667eea"
    
    # ✅ НОВЫЙ СПОСОБ для Pydantic V2
    model_config = ConfigDict(from_attributes=True)

class UserUpdate(BaseModel):
    email: Optional[str] = None
    avatar_color: Optional[str] = None

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class HabitCreate(BaseModel):
    title: str
    description: Optional[str] = ""

class HabitResponse(BaseModel):
    id: int
    title: str
    description: str
    completed: bool
    current_streak: int = 0
    longest_streak: int = 0
    
    # ✅ НОВЫЙ СПОСОБ для Pydantic V2
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

# ========== СОЗДАНИЕ ТАБЛИЦ ==========
Base.metadata.create_all(bind=engine)

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
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
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

# ========== ЭНДПОИНТЫ ==========

@app.get("/")
def root():
    return {"message": "Habit Tracker API"}

# ========== ФРОНТЕНД (ВСТРОЕННЫЙ HTML) ==========
@app.get("/frontend", response_class=HTMLResponse)
def frontend():
    return """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Habit Tracker</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a1a;
            min-height: 100vh;
            color: #e0e0e0;
        }
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 260px;
            height: 100%;
            background: #2d2d2d;
            color: #e0e0e0;
            padding: 25px 20px;
            z-index: 100;
            border-right: 1px solid #3a3a3a;
        }
        .sidebar h2 {
            font-size: 24px;
            margin-bottom: 30px;
            text-align: center;
            border-bottom: 2px solid #3a3a3a;
            padding-bottom: 15px;
            color: #f0f0f0;
            letter-spacing: 1px;
            font-weight: 300;
        }
        .sidebar nav a {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 15px;
            margin: 6px 0;
            color: #b0b0b0;
            text-decoration: none;
            border-radius: 10px;
            transition: all 0.2s;
            font-weight: 300;
            cursor: pointer;
        }
        .sidebar nav a:hover {
            background: #3a3a3a;
            color: #ffffff;
            transform: translateX(5px);
        }
        .sidebar nav a i {
            width: 24px;
            text-align: center;
            color: #888;
        }
        .sidebar nav a:hover i {
            color: #ffffff;
        }
        .main-content {
            margin-left: 260px;
            padding: 30px 35px;
            min-height: 100vh;
            background: #1a1a1a;
        }
        .card {
            background: #242424;
            border-radius: 16px;
            padding: 25px 30px;
            margin-bottom: 24px;
            border: 1px solid #333;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .card h2 {
            color: #f0f0f0;
            margin-bottom: 20px;
            border-bottom: 1px solid #333;
            padding-bottom: 12px;
            font-weight: 300;
            letter-spacing: 0.5px;
        }
        .card h2 i {
            color: #888;
            margin-right: 10px;
        }
        input, textarea {
            width: 100%;
            padding: 12px 16px;
            margin: 8px 0 16px;
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 10px;
            font-size: 14px;
            color: #e0e0e0;
            transition: 0.3s;
        }
        input:focus, textarea:focus {
            outline: none;
            border-color: #666;
            background: #1f1f1f;
        }
        input::placeholder, textarea::placeholder {
            color: #555;
        }
        button {
            background: #333;
            color: #e0e0e0;
            border: 1px solid #444;
            padding: 10px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s;
            font-weight: 400;
            margin-right: 10px;
        }
        button:hover {
            background: #444;
            border-color: #666;
            color: #ffffff;
        }
        button.danger {
            background: #3d1a1a;
            border-color: #5a1a1a;
            color: #e08080;
        }
        button.danger:hover {
            background: #5a1a1a;
            border-color: #8a2a2a;
            color: #ff9999;
        }
        button.success {
            background: #1a3a2a;
            border-color: #2a5a3a;
            color: #80d0a0;
        }
        button.success:hover {
            background: #2a4a3a;
            border-color: #3a7a4a;
            color: #a0e0b0;
        }
        .habit-item {
            background: #1a1a1a;
            border: 1px solid #2d2d2d;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: 0.3s;
        }
        .habit-item:hover {
            border-color: #444;
            background: #1f1f1f;
        }
        .habit-item.completed {
            background: #1a2a1a;
            border-color: #2d4a2d;
            opacity: 0.8;
        }
        .habit-item.completed .habit-title {
            text-decoration: line-through;
            color: #80d0a0;
        }
        .habit-title {
            font-size: 18px;
            font-weight: 400;
            color: #f0f0f0;
            letter-spacing: 0.3px;
        }
        .habit-desc {
            font-size: 14px;
            color: #888;
            margin-top: 4px;
        }
        .habit-streak {
            font-size: 13px;
            color: #b08040;
            margin-top: 8px;
            padding-top: 6px;
            border-top: 1px solid #2a2a2a;
        }
        .message {
            padding: 12px 18px;
            border-radius: 10px;
            margin-bottom: 16px;
            display: none;
            font-weight: 300;
        }
        .message.success {
            background: #1a3a2a;
            color: #80d0a0;
            border: 1px solid #2a5a3a;
            display: block;
        }
        .message.error {
            background: #3d1a1a;
            color: #e08080;
            border: 1px solid #5a1a1a;
            display: block;
        }
        .hidden { display: none; }
        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 400;
            margin-left: 10px;
            letter-spacing: 0.3px;
        }
        .badge.active {
            background: #1a4a2a;
            color: #80d0a0;
            border: 1px solid #2d6a3a;
        }
        .badge.inactive {
            background: #3d1a1a;
            color: #e08080;
            border: 1px solid #5a2a2a;
        }
        .avatar {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            margin-bottom: 15px;
            border: 2px solid #333;
        }
        .stat-card {
            background: #1a1a1a;
            border: 1px solid #2d2d2d;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            margin-bottom: 16px;
        }
        .stat-number {
            font-size: 36px;
            font-weight: 300;
            color: #f0f0f0;
            letter-spacing: 1px;
        }
        .stat-card div:last-child {
            color: #888;
            font-size: 14px;
            margin-top: 4px;
            font-weight: 300;
        }
        @media (max-width: 768px) {
            .sidebar { width: 70px; padding: 20px 10px; }
            .sidebar h2 { font-size: 0; }
            .sidebar h2::before { content: "📊"; font-size: 24px; }
            .sidebar nav a span { display: none; }
            .sidebar nav a i { font-size: 20px; margin: 0 auto; }
            .sidebar nav a { justify-content: center; }
            .main-content { margin-left: 70px; padding: 20px 15px; }
            .card { padding: 18px; }
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>Habit Tracker</h2>
        <nav>
            <a href="#" data-page="habits"><i class="fas fa-calendar-check"></i> <span>Привычки</span></a>
            <a href="#" data-page="profile"><i class="fas fa-user"></i> <span>Профиль</span></a>
            <a href="#" data-page="settings"><i class="fas fa-cog"></i> <span>Настройки</span></a>
            <a href="#" id="logoutBtn"><i class="fas fa-sign-out-alt"></i> <span>Выйти</span></a>
        </nav>
    </div>

    <div class="main-content">
        <div id="authForm" class="card">
            <h2><i class="fas fa-user-circle"></i> Вход / Регистрация</h2>
            <input type="text" id="username" placeholder="Имя пользователя">
            <input type="password" id="password" placeholder="Пароль">
            <button onclick="register()"><i class="fas fa-user-plus"></i> Регистрация</button>
            <button onclick="login()" class="success"><i class="fas fa-sign-in-alt"></i> Вход</button>
            <div id="authMessage" class="message"></div>
        </div>

        <div id="habitsPage" class="hidden">
            <div class="card">
                <h2><i class="fas fa-plus-circle"></i> Новая привычка</h2>
                <input type="text" id="habitTitle" placeholder="Название привычки">
                <textarea id="habitDesc" rows="2" placeholder="Описание (необязательно)"></textarea>
                <button onclick="createHabit()"><i class="fas fa-save"></i> Добавить</button>
            </div>
            <div class="card">
                <h2><i class="fas fa-list-check"></i> Мои привычки</h2>
                <div id="habitsList"></div>
            </div>
        </div>

        <div id="profilePage" class="hidden">
            <div class="card"><h2><i class="fas fa-user"></i> Мой профиль</h2><div id="profileInfo"></div></div>
            <div class="card"><h2><i class="fas fa-chart-line"></i> Статистика</h2><div id="statsInfo"></div></div>
        </div>

        <div id="settingsPage" class="hidden">
            <div class="card"><h2><i class="fas fa-envelope"></i> Email</h2><input type="email" id="emailInput" placeholder="Email"><button onclick="updateEmail()" class="success">Обновить email</button></div>
            <div class="card"><h2><i class="fas fa-palette"></i> Цвет аватара</h2><input type="color" id="avatarColorInput"><button onclick="updateAvatarColor()">Изменить цвет</button></div>
            <div class="card"><h2><i class="fas fa-key"></i> Сменить пароль</h2><input type="password" id="oldPassword" placeholder="Старый пароль"><input type="password" id="newPassword" placeholder="Новый пароль"><button onclick="changePassword()">Сменить пароль</button></div>
            <div class="card"><h2><i class="fas fa-trash-alt"></i> Удалить аккаунт</h2><button onclick="deleteAccount()" class="danger">Удалить мой аккаунт</button></div>
        </div>
    </div>

    <script>
        let token = null, currentUser = null;
        const API_URL = window.location.origin;

        function showMessage(el, text, type) {
            const msg = document.getElementById(el);
            msg.textContent = text;
            msg.className = 'message ' + type;
            setTimeout(() => msg.className = 'message', 3000);
        }

        async function register() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            try {
                const res = await fetch(API_URL + '/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                if (res.ok) showMessage('authMessage', 'Регистрация успешна! Теперь войдите.', 'success');
                else { const err = await res.json(); showMessage('authMessage', err.detail || 'Ошибка', 'error'); }
            } catch(e) { showMessage('authMessage', 'Ошибка соединения', 'error'); }
        }

        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            try {
                const res = await fetch(API_URL + '/token', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password)
                });
                if (res.ok) {
                    const data = await res.json();
                    token = data.access_token;
                    document.getElementById('authForm').classList.add('hidden');
                    showPage('habits');
                    await loadCurrentUser();
                } else showMessage('authMessage', 'Неверное имя или пароль', 'error');
            } catch(e) { showMessage('authMessage', 'Ошибка соединения', 'error'); }
        }

        async function loadCurrentUser() {
            try {
                const res = await fetch(API_URL + '/profile', {headers: {'Authorization': 'Bearer ' + token}});
                if (res.ok) currentUser = await res.json();
            } catch(e) {}
        }

        function showPage(page) {
            document.getElementById('habitsPage').classList.add('hidden');
            document.getElementById('profilePage').classList.add('hidden');
            document.getElementById('settingsPage').classList.add('hidden');
            document.getElementById(page + 'Page').classList.remove('hidden');
            if (page === 'profile') loadProfile();
            if (page === 'habits') loadHabits();
        }

        document.querySelectorAll('.sidebar nav a[data-page]').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                showPage(link.dataset.page);
            });
        });
        document.getElementById('logoutBtn').addEventListener('click', (e) => {
            e.preventDefault();
            token = null;
            document.getElementById('authForm').classList.remove('hidden');
            document.getElementById('habitsPage').classList.add('hidden');
            document.getElementById('profilePage').classList.add('hidden');
            document.getElementById('settingsPage').classList.add('hidden');
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
        });

        async function loadHabits() {
            try {
                const res = await fetch(API_URL + '/habits', {headers: {'Authorization': 'Bearer ' + token}});
                if (res.ok) {
                    const habits = await res.json();
                    const container = document.getElementById('habitsList');
                    if (habits.length === 0) container.innerHTML = '<p style="text-align:center; color:#888;"><i class="fas fa-smile-wink"></i> Пока нет привычек. Добавьте первую!</p>';
                    else container.innerHTML = habits.map(h => `
                        <div class="habit-item ${h.completed ? 'completed' : ''}">
                            <div>
                                <div class="habit-title">${escapeHtml(h.title)}<span class="badge ${h.completed ? 'active' : 'inactive'}">${h.completed ? '✓ Выполнено' : '○ В процессе'}</span></div>
                                <div class="habit-desc">${escapeHtml(h.description) || '—'}</div>
                                <div class="habit-streak">🔥 <strong>${h.current_streak || 0}</strong> дней подряд ${h.longest_streak > 0 ? '| 🏆 Рекорд: ' + h.longest_streak : ''}</div>
                            </div>
                            <div>
                                <button onclick="toggleComplete(${h.id})" class="success"><i class="fas fa-check-circle"></i></button>
                                <button onclick="deleteHabit(${h.id})" class="danger"><i class="fas fa-trash-alt"></i></button>
                            </div>
                        </div>
                    `).join('');
                }
            } catch(e) { console.error(e); }
        }

        async function createHabit() {
            const title = document.getElementById('habitTitle').value;
            const desc = document.getElementById('habitDesc').value;
            if (!title.trim()) return;
            await fetch(API_URL + '/habits', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({title, description: desc})
            });
            document.getElementById('habitTitle').value = '';
            document.getElementById('habitDesc').value = '';
            loadHabits();
        }

        async function toggleComplete(id) {
            await fetch(API_URL + '/habits/' + id + '/complete', {method: 'PUT', headers: {'Authorization': 'Bearer ' + token}});
            loadHabits();
        }

        async function deleteHabit(id) {
            if (confirm('Удалить привычку?')) {
                await fetch(API_URL + '/habits/' + id, {method: 'DELETE', headers: {'Authorization': 'Bearer ' + token}});
                loadHabits();
            }
        }

        async function loadProfile() {
            try {
                const res = await fetch(API_URL + '/profile', {headers: {'Authorization': 'Bearer ' + token}});
                if (res.ok) {
                    const user = await res.json();
                    const habitsRes = await fetch(API_URL + '/habits', {headers: {'Authorization': 'Bearer ' + token}});
                    const habits = await habitsRes.json();
                    const total = habits.length;
                    const completedToday = habits.filter(h => h.completed).length;
                    const totalStreak = habits.reduce((s, h) => s + (h.current_streak || 0), 0);
                    const maxStreak = Math.max(...habits.map(h => h.longest_streak || 0), 0);
                    document.getElementById('profileInfo').innerHTML = `
                        <div class="avatar" style="background: ${user.avatar_color}"><i class="fas fa-user" style="font-size: 32px; color: white;"></i></div>
                        <p><strong>Имя:</strong> ${escapeHtml(user.username)}</p>
                        <p><strong>Email:</strong> ${user.email || 'Не указан'}</p>
                        <p><strong>Дата регистрации:</strong> ${user.created_at || '—'}</p>
                    `;
                    document.getElementById('statsInfo').innerHTML = `
                        <div class="stat-card"><div class="stat-number">${total}</div><div>Всего привычек</div></div>
                        <div class="stat-card"><div class="stat-number">${completedToday}</div><div>Выполнено сегодня</div></div>
                        <div class="stat-card"><div class="stat-number">${totalStreak}</div><div>Всего дней подряд 🔥</div></div>
                        <div class="stat-card"><div class="stat-number">${maxStreak}</div><div>Рекордная серия 🏆</div></div>
                    `;
                }
            } catch(e) {}
        }

        async function updateEmail() {
            const email = document.getElementById('emailInput').value;
            await fetch(API_URL + '/profile', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({email})
            });
            alert('Email обновлён!');
        }

        async function updateAvatarColor() {
            const color = document.getElementById('avatarColorInput').value;
            await fetch(API_URL + '/profile', {
                method: 'PUT',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({avatar_color: color})
            });
            alert('Цвет обновлён!');
        }

        async function changePassword() {
            const oldPwd = document.getElementById('oldPassword').value;
            const newPwd = document.getElementById('newPassword').value;
            const res = await fetch(API_URL + '/change-password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token},
                body: JSON.stringify({old_password: oldPwd, new_password: newPwd})
            });
            if (res.ok) alert('Пароль изменён!');
            else alert('Старый пароль неверен');
        }

        async function deleteAccount() {
            if (confirm('Точно удалить аккаунт? ВСЕ ДАННЫЕ БУДУТ ПОТЕРЯНЫ!')) {
                await fetch(API_URL + '/delete-account', {method: 'DELETE', headers: {'Authorization': 'Bearer ' + token}});
                alert('Аккаунт удалён');
                location.reload();
            }
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
    """

# ========== API ЭНДПОИНТЫ ==========

@app.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(
        username=user.username,
        hashed_password=hashed_password,
        created_at=date.today().isoformat()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
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
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/profile", response_model=UserResponse)
def get_profile(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/profile", response_model=UserResponse)
def update_profile(profile: UserUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if profile.email is not None:
        current_user.email = profile.email
    if profile.avatar_color is not None:
        current_user.avatar_color = profile.avatar_color
    db.commit()
    db.refresh(current_user)
    return current_user

@app.post("/change-password")
def change_password(data: PasswordChange, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password is incorrect")
    current_user.hashed_password = get_password_hash(data.new_password)
    db.commit()
    return {"message": "Password changed successfully"}

@app.delete("/delete-account")
def delete_account(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(Habit).filter(Habit.user_id == current_user.id).delete()
    db.delete(current_user)
    db.commit()
    return {"message": "Account deleted"}

@app.post("/habits", response_model=HabitResponse)
def create_habit(habit: HabitCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_habit = Habit(title=habit.title, description=habit.description, user_id=current_user.id)
    db.add(new_habit)
    db.commit()
    db.refresh(new_habit)
    return new_habit

@app.get("/habits", response_model=List[HabitResponse])
def get_habits(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    habits = db.query(Habit).filter(Habit.user_id == current_user.id).all()
    return habits

@app.get("/habits/{habit_id}", response_model=HabitResponse)
def get_habit(habit_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    habit = db.query(Habit).filter(Habit.id == habit_id, Habit.user_id == current_user.id).first()
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    return habit

@app.put("/habits/{habit_id}", response_model=HabitResponse)
def update_habit(habit_id: int, habit: HabitCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(Habit).filter(Habit.id == habit_id, Habit.user_id == current_user.id).first()
    if not existing:
        raise HTTPException(status_code=404, detail="Habit not found")
    existing.title = habit.title
    existing.description = habit.description
    db.commit()
    db.refresh(existing)
    return existing

# ========== ИСПРАВЛЕННЫЙ ЭНДПОИНТ ==========
@app.put("/habits/{habit_id}/complete", response_model=HabitResponse)
def complete_habit(habit_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    habit = db.query(Habit).filter(Habit.id == habit_id, Habit.user_id == current_user.id).first()
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    # ✅ НОВАЯ ПРАВИЛЬНАЯ ЛОГИКА
    now = datetime.now(pytz.UTC)
    today = now.date()
    
    if habit.last_completed_date:
        last_date = habit.last_completed_date.date()
        if last_date == today:
            return habit
    
    habit.completed = not habit.completed
    
    if habit.completed:
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
    else:
        if habit.current_streak > 0:
            habit.current_streak -= 1
    
    db.commit()
    db.refresh(habit)
    return habit

@app.delete("/habits/{habit_id}")
def delete_habit(habit_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    habit = db.query(Habit).filter(Habit.id == habit_id, Habit.user_id == current_user.id).first()
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    db.delete(habit)
    db.commit()
    return {"message": "Habit deleted"}