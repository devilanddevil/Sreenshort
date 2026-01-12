import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('idle_tracker.db')
c = conn.cursor()

new_user = 'admin'
new_pass = '12345'
hashed_pw = generate_password_hash(new_pass)

# 1. Purane complex user ko update karo 'admin' pe
c.execute("UPDATE users SET username = ?, password_hash = ? WHERE username LIKE 'pradum%yadav'", (new_user, hashed_pw))

if c.rowcount == 0:
    # Aggar update nahi hua (matlab user nahi mila), toh naya bana do
    print("User nahi mila, naya 'admin' user bana rahe hain...")
    try:
        c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", (new_user, hashed_pw, True))
    except sqlite3.IntegrityError:
        # Agar admin pehle se hai toh sirf password reset karo
        c.execute("UPDATE users SET password_hash = ? WHERE username = ?", (hashed_pw, new_user))

conn.commit()
conn.close()

print(f"\n✅ DONE! Login Details Updated:")
print(f"👉 Username: {new_user}")
print(f"👉 Password: {new_pass}")
