import sqlite3
from werkzeug.security import generate_password_hash

# Connect to DB
conn = sqlite3.connect('idle_tracker.db')
c = conn.cursor()

# Naya username aur password set karte hain
new_user = 'admin'
new_pass = '12345'
hashed_pw = generate_password_hash(new_pass)

print("Fixing Login...")

# 1. Check karo koi bhi user hai kya?
c.execute("SELECT count(*) FROM users")
count = c.fetchone()[0]

if count > 0:
    # Aggar users hain to SABKA password reset kardo aur pehle wale ko admin bana do
    print(f"Update existing users ({count} found)...")
    c.execute(f"UPDATE users SET username='{new_user}', password_hash=?, is_admin=1 WHERE id=1", (hashed_pw,))
else:
    # Agar user nahi hai toh naya banao
    print("Creating new user...")
    c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", (new_user, hashed_pw, True))

conn.commit()
conn.close()

print("\n✅ LOGIN FIXED!")
print("--------------------------------")
print(f"USER: {new_user}")
print(f"PASS: {new_pass}")
print("--------------------------------")
print("Ab app restart karke login karein.")
