from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import json, os, time, hashlib, re, secrets, uuid
from datetime import datetime
from collections import defaultdict
from functools import wraps

app = Flask(__name__, static_folder=".")

# ─── SECRET KEY: use env var on Render, fallback for local ──────────
# On Render: set SECRET_KEY in Environment Variables dashboard
# Locally:   any fixed string works
app.secret_key = os.environ.get("SECRET_KEY", "slambook-local-dev-key-change-on-render")

# ─── SESSION COOKIE: works on both HTTP (local) and HTTPS (Render) ──
app.config.update(
    SESSION_COOKIE_SAMESITE="None",   # needed for cross-origin requests
    SESSION_COOKIE_SECURE=os.environ.get("RENDER", False),  # True on Render (HTTPS), False locally
    SESSION_COOKIE_HTTPONLY=True,
)

# ─── CORS: allow all origins (same-origin on Render, localhost locally) ──
CORS(app, supports_credentials=True, origins="*")

# ─── SECURITY: Rate Limiter ─────────────────────────────────────────
rate_store = defaultdict(list)
def rate_limit(max_req=20, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            rate_store[ip] = [t for t in rate_store[ip] if now - t < window]
            if len(rate_store[ip]) >= max_req:
                return jsonify({"error": "Too many requests. Please slow down."}), 429
            rate_store[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ─── SECURITY: Input Sanitizer ──────────────────────────────────────
def sanitize(text, max_len=500):
    if not isinstance(text, str): return ""
    text = text.strip()[:max_len]
    text = re.sub(r'<[^>]+>', '', text)           # Strip HTML tags
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)  # Strip JS proto
    return text

def sanitize_email(email):
    email = sanitize(email, 100)
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return None
    return email.lower()

# ─── SECURITY: Password Hashing ─────────────────────────────────────
def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + ':' + h.hex()

def verify_password(password, stored):
    try:
        salt, _ = stored.split(':')
        return stored == hash_password(password, salt)
    except:
        return False

# ─── DATA FILES ──────────────────────────────────────────────────────
USERS_FILE    = "users.json"
SLAMBOOKS_FILE = "slambooks.json"
RESPONSES_FILE = "responses.json"

def load_json(path):
    if not os.path.exists(path): return {}
    with open(path) as f: return json.load(f)

def save_json(path, data):
    with open(path, 'w') as f: json.dump(data, f, indent=2)

def load_list(path):
    if not os.path.exists(path): return []
    with open(path) as f: return json.load(f)

def save_list(path, data):
    with open(path, 'w') as f: json.dump(data, f, indent=2)

# ─── AUTH HELPERS ────────────────────────────────────────────────────
def current_user():
    uid = session.get('user_id')
    if not uid: return None
    users = load_json(USERS_FILE)
    return users.get(uid)

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Not logged in"}), 401
        return f(*args, **kwargs)
    return wrapped

# ─── STATIC ──────────────────────────────────────────────────────────
@app.route("/")
def index(): return send_from_directory(".", "index.html")

@app.route("/<path:p>")
def static_files(p): return send_from_directory(".", p)

# ─── AUTH ROUTES ─────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
@rate_limit(5, 60)
def register():
    data = request.get_json(silent=True) or {}
    username = sanitize(data.get("username",""), 30)
    email    = sanitize_email(data.get("email",""))
    password = data.get("password","")

    if not username or len(username) < 3:
        return jsonify({"error": "Username must be 3+ characters"}), 400
    if not email:
        return jsonify({"error": "Invalid email"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be 6+ characters"}), 400

    users = load_json(USERS_FILE)
    # Check uniqueness
    for u in users.values():
        if u['username'].lower() == username.lower():
            return jsonify({"error": "Username taken"}), 409
        if u['email'] == email:
            return jsonify({"error": "Email already registered"}), 409

    uid = str(uuid.uuid4())
    # Each user gets a personal slambook token
    slambook_token = secrets.token_urlsafe(12)
    users[uid] = {
        "id": uid,
        "username": username,
        "email": email,
        "password": hash_password(password),
        "slambook_token": slambook_token,
        "created_at": datetime.utcnow().isoformat()
    }
    save_json(USERS_FILE, users)
    session['user_id'] = uid
    return jsonify({"success": True, "username": username, "slambook_token": slambook_token}), 201

@app.route("/api/login", methods=["POST"])
@rate_limit(10, 60)
def login():
    data = request.get_json(silent=True) or {}
    username = sanitize(data.get("username",""), 30)
    password = data.get("password","")

    users = load_json(USERS_FILE)
    found = None
    for u in users.values():
        if u['username'].lower() == username.lower():
            found = u; break

    if not found or not verify_password(password, found['password']):
        return jsonify({"error": "Invalid username or password"}), 401

    session['user_id'] = found['id']
    return jsonify({
        "success": True,
        "username": found['username'],
        "slambook_token": found['slambook_token']
    })

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me", methods=["GET"])
def me():
    u = current_user()
    if not u: return jsonify({"logged_in": False}), 200
    return jsonify({
        "logged_in": True,
        "username": u['username'],
        "slambook_token": u['slambook_token']
    })

# ─── SLAMBOOK LINK ROUTES ────────────────────────────────────────────
@app.route("/api/link/<token>", methods=["GET"])
@rate_limit(30, 60)
def get_owner_by_token(token):
    token = sanitize(token, 30)
    users = load_json(USERS_FILE)
    for u in users.values():
        if u.get('slambook_token') == token:
            return jsonify({"owner": u['username'], "valid": True})
    return jsonify({"valid": False}), 404

# ─── SUBMIT RESPONSE (friend fills) ─────────────────────────────────
@app.route("/api/submit/<token>", methods=["POST"])
@rate_limit(5, 300)  # Max 5 per 5 min per IP per token
def submit_response(token):
    token = sanitize(token, 30)
    users = load_json(USERS_FILE)
    owner = None
    for u in users.values():
        if u.get('slambook_token') == token:
            owner = u; break
    if not owner:
        return jsonify({"error": "Invalid slambook link"}), 404

    data = request.get_json(silent=True) or {}
    # Sanitize all fields
    fields = [
        "full_name","nickname","dob","zodiac","contact",
        "fav_color","fav_food","fav_movie","fav_singer","fav_actor",
        "fav_place","fav_subject","fav_hobby","fav_season","fav_quote",
        "goal","dream_job","in_10_years","want_to_achieve",
        "three_words","biggest_fear","strength","hidden_talent",
        "embarrassing_moment","crush",
        "first_impression","what_changed","fav_memory","like_most",
        "annoys_me","secret_between_us","movie_title",
        "dedicate_song","song_line","theme_song",
        "coffee_tea","night_day","love_money","call_text",
        "mountains_beach","intro_extro",
        "message","remember_me"
    ]
    entry = {}
    for f in fields:
        entry[f] = sanitize(data.get(f,""), 500)

    if not entry['full_name']:
        return jsonify({"error": "Full name is required"}), 400

    entry['owner_id']  = owner['id']
    entry['entry_id']  = str(uuid.uuid4())[:8]
    entry['timestamp'] = datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")
    entry['ip_hash']   = hashlib.sha256(request.remote_addr.encode()).hexdigest()[:12]  # Store hash, not raw IP

    responses = load_list(RESPONSES_FILE)
    # Prevent duplicate submissions from same IP to same slambook
    for r in responses:
        if r.get('owner_id') == owner['id'] and r.get('ip_hash') == entry['ip_hash']:
            return jsonify({"error": "You already filled this slambook!"}), 409

    responses.append(entry)
    save_list(RESPONSES_FILE, responses)
    return jsonify({"success": True, "message": f"Slam delivered to {owner['username']}! 💌"}), 201

# ─── GET MY SLAMBOOK RESPONSES ────────────────────────────────────────
@app.route("/api/my-responses", methods=["GET"])
@login_required
@rate_limit(30, 60)
def my_responses():
    u = current_user()
    responses = load_list(RESPONSES_FILE)
    mine = [r for r in responses if r.get('owner_id') == u['id']]
    # Remove IP hash before sending to client
    for r in mine: r.pop('ip_hash', None)
    return jsonify(mine)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Render sets PORT automatically
    print(f"🌸 Slambook running → http://127.0.0.1:{port}")
    app.run(debug=False, host="0.0.0.0", port=port)