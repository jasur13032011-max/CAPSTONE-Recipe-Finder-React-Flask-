# CAPSTONE-Recipe-Finder-React-Flask-Bu loyiha to'liq funksional bo'lib, xavfsizlik (JWT, Protected Routes), optimallashtirish (React.memo, AbortController), va clean-code prinsiplariga mos keladi.

📂 Loyiha Strukturasi (File Tree)
Loyihani tashkil qilish uchun eng qulay va kengaytiriluvchi struktura:

Plaintext
recipe-app/
├── backend/
│   ├── app.py                  # Flask ilovasi kirish nuqtasi
│   ├── config.py               # Sozlamalar va DB konfiguratsiyasi
│   ├── database.py             # SQLAlchemy ulanishi
│   ├── models.py               # DB Modellar (User, Recipe, Favorite, Comment)
│   ├── requirements.txt        # Backend kutubxonalari
│   └── .env                    # Maxfiy kalitlar va DB URL
└── frontend/
    ├── src/
    │   ├── assets/             # Rasmlar va stillar
    │   ├── components/         # Umumiy komponentlar (Navbar, Card, ProtectedRoute)
    │   ├── context/            # AuthContext, ThemeContext
    │   ├── hooks/              # useFetch, useDebounce, useLocalStorage
    │   ├── pages/              # 7+ sahifalar (Home, Recipes, Detail, etc.)
    │   ├── App.jsx             # Routers va asosiy render
    │   ├── main.jsx            # Vite kirish fayli
    │   └── index.css           # Tailwind CSS sozlamalari
    ├── vite.config.js
    └── tailwind.config.js
🖥️ 1. Backend (Flask + PostgreSQL)
Avvalo, kerakli paketlarni o'rnatish uchun requirements.txt faylini yaratamiz:

Plaintext
Flask==3.0.2
Flask-SQLAlchemy==3.1.1
Flask-Cors==4.0.0
PyJWT==2.8.0
psycopg2-binary==2.9.9
python-dotenv==1.0.1
gunicorn==21.2.0
backend/models.py (Ma'lumotlar bazasi modellari)
Python
from database import db
from datetime import datetime
import werkzeug.security as security

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    favorites = db.relationship('Favorite', backref='user', lazy=True, cascade="all, delete-orphan")
    comments = db.relationship('Comment', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = security.generate_password_hash(password)

    def check_password(self, password):
        return security.check_password_hash(self.password_hash, password)

class Recipe(db.Model):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ingredients = db.Column(db.Text, nullable=False) # Vergul bilan ajratilgan
    instructions = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    comments = db.relationship('Comment', backref='recipe', lazy=True, cascade="all, delete-orphan")

class Favorite(db.Model):
    __tablename__ = 'favorites'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipes.id'), nullable=False)

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipes.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
backend/app.py (API va Auth middleware)
Python
import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from database import db
from models import User, Recipe, Favorite, Comment

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:password@localhost:5432/recipe_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-super-secret-key')

db.init_app(app)

# Ma'lumotlar bazasini yaratish (Dastlabki ishga tushirish uchun)
with app.app_context():
    db.create_all()

# --- JWT DEKORATORI ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token yetishmayapti!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'Foydalanuvchi topilmadi!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token muddati tugagan!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Yaroqsiz token!'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# --- AUTH API ---
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Barcha maydonlarni to\'ldiring!'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email allaqachon ro\'yxatdan o\'tgan!'}), 400

    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'Muvaffaqiyatli ro\'yxatdan o\'tdingiz!'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email va parolni kiriting!'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Email yoki parol xato!'}), 401
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'user': {'id': user.id, 'username': user.username, 'email': user.email}
    }), 200

# --- RECIPES API ---
@app.route('/api/recipes', methods=['GET'])
def get_recipes():
    query_str = request.args.get('q', '')
    category = request.args.get('category', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 6, type=int)
    
    stmt = Recipe.query
    if query_str:
        stmt = stmt.filter(Recipe.title.ilike(f'%{query_str}%') | Recipe.description.ilike(f'%{query_str}%'))
    if category:
        stmt = stmt.filter(Recipe.category.ilike(category))
        
    pagination = stmt.paginate(page=page, per_page=per_page, error_out=False)
    
    recipes_list = []
    for r in pagination.items:
        recipes_list.append({
            'id': r.id, 'title': r.title, 'description': r.description,
            'category': r.category, 'image_url': r.image_url
        })
        
    return jsonify({
        'recipes': recipes_list,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': pagination.page
    }), 200

@app.route('/api/recipes/<int:id>', methods=['GET'])
def get_recipe_detail(id):
    recipe = Recipe.query.get_or_404(id)
    return jsonify({
        'id': recipe.id,
        'title': recipe.title,
        'description': recipe.description,
        'ingredients': recipe.ingredients.split(','),
        'instructions': recipe.instructions,
        'category': recipe.category,
        'image_url': recipe.image_url
    }), 200

# --- FAVORITES API ---
@app.route('/api/favorites', methods=['GET', 'POST'])
@token_required
def manage_favorites(current_user):
    if request.method == 'POST':
        data = request.get_json()
        recipe_id = data.get('recipe_id')
        if not recipe_id:
            return jsonify({'message': 'Recipe ID talab qilinadi'}), 400
            
        existing = Favorite.query.filter_by(user_id=current_user.id, recipe_id=recipe_id).first()
        if existing:
            return jsonify({'message': 'Allaqachon sevimlilarga qo\'shilgan'}), 400
            
        fav = Favorite(user_id=current_user.id, recipe_id=recipe_id)
        db.session.add(fav)
        db.session.commit()
        return jsonify({'message': 'Sevimlilarga qo\'shildi'}), 201

    # GET so'rovi uchun
    favs = Favorite.query.filter_by(user_id=current_user.id).all()
    recipes = [Recipe.query.get(f.recipe_id) for f in favs]
    return jsonify([{
        'id': r.id, 'title': r.title, 'description': r.description,
        'category': r.category, 'image_url': r.image_url
    } for r in recipes if r]), 200

@app.route('/api/favorites/<int:recipe_id>', methods=['DELETE'])
@token_required
def delete_favorite(current_user, recipe_id):
    fav = Favorite.query.filter_by(user_id=current_user.id, recipe_id=recipe_id).first()
    if not fav:
        return jsonify({'message': 'Topilmadi'}), 404
    db.session.delete(fav)
    db.session.commit()
    return jsonify({'message': 'Sevimlilardan o\'chirildi'}), 200

# --- COMMENTS API ---
@app.route('/api/recipes/<int:recipe_id>/comments', methods=['GET', 'POST'])
def manage_comments(recipe_id):
    if request.method == 'POST':
        @token_required
        def post_comment(current_user):
            data = request.get_json()
            content = data.get('content')
            if not content:
                return jsonify({'message': 'Izoh bo\'sh bo\'lishi mumkin emas'}), 400
            comm = Comment(content=content, user_id=current_user.id, recipe_id=recipe_id)
            db.session.add(comm)
            db.session.commit()
            return jsonify({
                'id': comm.id,
                'content': comm.content,
                'username': current_user.username,
                'created_at': comm.created_at.isoformat()
            }), 201
        return post_comment()
        
    # GET so'rovi uchun
    comments = Comment.query.filter_by(recipe_id=recipe_id).order_by(Comment.created_at.desc()).all()
    return jsonify([{
        'id': c.id,
        'content': c.content,
        'username': User.query.get(c.user_id).username,
        'created_at': c.created_at.isoformat()
    } for c in comments]), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
💻 2. Frontend (React + Vite + Tailwind CSS)
Custom Hooks (src/hooks/)
useLocalStorage.js
JavaScript
import { useState, useEffect } from 'react';

export default function useLocalStorage(key, initialValue) {
  const [value, setValue] = useState(() => {
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      return initialValue;
    }
  });

  useEffect(() => {
    localStorage.setItem(key, JSON.stringify(value));
  }, [key, value]);

  return [value, setValue];
}
useDebounce.js
JavaScript
import { useState, useEffect } from 'react';

export default function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => clearTimeout(handler);
  }, [value, delay]);

  return debouncedValue;
}
useFetch.js (AbortController bilan)
JavaScript
import { useState, useEffect } from 'react';

export default function useFetch(url, options = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const abortController = new AbortController();
    setLoading(true);

    fetch(url, { ...options, signal: abortController.signal })
      .then((res) => {
        if (!res.ok) throw new Error('Ma\'lumot yuklashda xatolik yuz berdi.');
        return res.json();
      })
      .then((data) => {
        setData(data);
        setError(null);
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          setError(err.message);
        }
      })
      .finally(() => setLoading(false));

    return () => abortController.abort();
  }, [url]);

  return { data, loading, error };
}
Context Provayderlari (src/context/)
ThemeContext.jsx (Dark Mode)
JavaScript
import React, { createContext, useContext, useEffect } from 'react';
import useLocalStorage from '../hooks/useLocalStorage';

const ThemeContext = createContext();

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useLocalStorage('theme', 'light');

  useEffect(() => {
    const root = window.document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [theme]);

  const toggleTheme = () => setTheme(theme === 'light' ? 'dark' : 'light');

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
AuthContext.jsx (JWT & LocalStorage)
JavaScript
import React, { createContext, useContext, useState } from 'react';
import useLocalStorage from '../hooks/useLocalStorage';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [token, setToken] = useLocalStorage('token', null);
  const [user, setUser] = useLocalStorage('user', null);

  const login = (userData, userToken) => {
    setUser(userData);
    setToken(userToken);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
  };

  const isAuthenticated = !!token;

  return (
    <AuthContext.Provider value={{ user, token, isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
Router va Xavfsiz Yo'nalishlar (Protected Routes)
src/components/ProtectedRoute.jsx
JavaScript
import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? children : <Navigate to="/login" replace />;
}
src/App.jsx (7+ Sahifali Router tizimi)
JavaScript
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';

// Pages
import Home from './pages/Home';
import Recipes from './pages/Recipes';
import RecipeDetail from './pages/RecipeDetail';
import Favorites from './pages/Favorites';
import Profile from './pages/Profile';
import Login from './pages/Login';
import Register from './pages/Register';
import NotFound from './pages/NotFound';

// Components
import Navbar from './components/Navbar';
import ProtectedRoute from './components/ProtectedRoute';

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <Router>
          <div className="min-h-screen bg-white dark:bg-gray-900 text-gray-900 dark:text-white transition-colors duration-200">
            <Navbar />
            <main className="container mx-auto px-4 py-6">
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/recipes" element={<Recipes />} />
                <Route path="/recipes/:id" element={<RecipeDetail />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                
                {/* Himoyalangan sahifalar */}
                <Route path="/favorites" element={
                  <ProtectedRoute>
                    <Favorites />
                  </ProtectedRoute>
                } />
                <Route path="/profile" element={
                  <ProtectedRoute>
                    <Profile />
                  </ProtectedRoute>
                } />

                {/* 404 Sahifasi */}
                <Route path="*" element={<NotFound />} />
              </Routes>
            </main>
          </div>
        </Router>
      </AuthProvider>
    </ThemeProvider>
  );
}
Controlled Form namunalari
src/pages/Login.jsx (Kirish formasi va xatoliklarni boshqarish)
JavaScript
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await fetch('http://localhost:5000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await res.json();
      
      if (!res.ok) throw new Error(data.message || 'Xatolik yuz berdi');

      login(data.user, data.token);
      navigate('/profile');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto mt-10 p-6 bg-gray-100 dark:bg-gray-800 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-center">Tizimga kirish</h2>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block mb-1 font-medium">Email</label>
          <input 
            type="email" name="email" value={formData.email} onChange={handleChange} required 
            className="w-full p-2 border rounded dark:bg-gray-700 dark:border-gray-600"
          />
        </div>
        <div>
          <label className="block mb-1 font-medium">Parol</label>
          <input 
            type="password" name="password" value={formData.password} onChange={handleChange} required 
            className="w-full p-2 border rounded dark:bg-gray-700 dark:border-gray-600"
          />
        </div>
        <button 
          type="submit" disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 text-white p-2 rounded font-semibold transition"
        >
          {loading ? 'Yuklanmoqda...' : 'Kirish'}
        </button>
      </form>
    </div>
  );
}
React.memo va Optimallashtirish
src/components/RecipeCard.jsx
Bu komponent faqat recipe o'zgargandagina qayta render bo'ladi. Bu ko'plab ro'yxat elementlari render bo'lganda ishlash tezligini oshiradi.

JavaScript
import React from 'react';
import { Link } from 'react-router-dom';

const RecipeCard = React.memo(({ recipe, onFavoriteToggle, isFav }) => {
  return (
    <div className="border dark:border-gray-700 rounded-lg overflow-hidden shadow-sm hover:shadow-md transition">
      <img src={recipe.image_url || 'https://via.placeholder.com/300'} alt={recipe.title} className="w-full h-48 object-cover" />
      <div className="p-4">
        <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded dark:bg-blue-900 dark:text-blue-100">{recipe.category}</span>
        <h3 className="font-bold text-lg mt-2">{recipe.title}</h3>
        <p className="text-sm text-gray-600 dark:text-gray-300 mt-1 line-clamp-2">{recipe.description}</p>
        <div className="flex justify-between items-center mt-4">
          <Link to={`/recipes/${recipe.id}`} className="text-blue-600 hover:underline font-medium text-sm">Batafsil</Link>
          <button onClick={() => onFavoriteToggle(recipe.id)} className="text-2xl">
            {isFav ? '❤️' : '🤍'}
          </button>
        </div>
      </div>
    </div>
  );
});

export default RecipeCard;
🏗️ 3. Arxitektura Diagrammasi va Loyiha Hujjati
README.md (Loyihani ishga tushirish)
Markdown
# 🍲 Recipe App (React + Flask + PostgreSQL)

Bu to'liq funksional, xavfsiz va optimallashgan taomlar retseptlari loyihasi.

## 🛠️ Texnologiyalar:
* **Frontend:** React, Vite, React Router, Tailwind CSS, Context API.
* **Backend:** Flask, PostgreSQL, SQLAlchemy, PyJWT, CORS.

## 📦 O'rnatish tartibi:

### 1. Backend sozlash:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows uchun: venv\Scripts\activate
pip install -r requirements.txt
python app.py
2. Frontend sozlash:
Bash
cd frontend
npm install
npm run dev

---

## 🌟 Bonus: Deploy va TanStack Query Haqida
* **Deploy:** Frontend qismini osongina **Vercel** yoki **Netlify** platformasiga import qilish orqali deploy qila olasiz. Backend esa **Render.com** yoki **Railway** platformalariga yuklanib, PostgreSQL integratsiyasi oson ulanadi.
* **TanStack Query (React Query):** Agar keyinchalik ma'lumotlarni keshlashni yanada kuc
