# 🌸 My Slambook — Full Stack

A dreamy scrapbook-from-the-future themed online slambook with login, shareable friend links, and a full 40-question form.

## 📁 Files
```
app.py          → Flask backend
index.html      → Login + Dashboard (your page)
fill.html       → Friend fill page (shareable)
requirements.txt
users.json      → Created automatically
responses.json  → Created automatically
```

## 🚀 Run
```bash
pip install -r requirements.txt
python app.py
# Open → http://127.0.0.1:5000
```

## 🔄 Flow
1. **You** → Register/Login at `http://127.0.0.1:5000`
2. **Copy your link** shown on your dashboard
3. **Send the link** to your friends (e.g. `http://127.0.0.1:5000/fill.html?s=abc123`)
4. **Friends fill** the slambook — answers saved to YOUR account
5. **You view** all responses as cute cards, click any to read in full

## 🔐 Security
- **PBKDF2-SHA256** password hashing (100,000 iterations)
- **Rate limiting** — 5 req/5min for submissions, 10 req/min for auth
- **IP hashing** — raw IPs never stored, only SHA-256 hashes
- **Duplicate prevention** — one fill per IP per slambook
- **Input sanitization** — HTML/script tags stripped
- **Session-based auth** with secure random secret key
- **CORS** — localhost only
