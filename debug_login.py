import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash

conn = sqlite3.connect('idle_tracker.db')
c = conn.cursor()

# Fetch user
c.execute("SELECT id, username, password_hash FROM users WHERE username LIKE 'pradum%yadav'")
user = c.fetchone()
conn.close()

if user:
    user_id, username, stored_hash = user
    print(f"DEBUG IN DB -> Username: '{username}'")
    print(f"DEBUG IN DB -> Hash: {stored_hash[:20]}...")
    
    # Test Passwords
    test_pass = "12345"
    is_valid = check_password_hash(stored_hash, test_pass)
    print(f"DEBUG TEST -> Checking password '{test_pass}': {is_valid}")
    
    if is_valid:
        print("\n✅ Verification SUCCESS: Password is correct in DB.")
        print(f"👉 Please copy-paste this username EXACTLY: '{username}'")
    else:
        print("\n❌ Verification FAILED: Hash mismatch.")
else:
    print("User not found via LIKE query.")
