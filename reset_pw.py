from werkzeug.security import generate_password_hash
import sqlite3

# Naya password
new_password = "12345"
hashed_pw = generate_password_hash(new_password)

try:
    conn = sqlite3.connect('idle_tracker.db')
    c = conn.cursor()
    
    # Pradum yadav ko dhoondh ke password update karte hain
    # Note: Hum LIKE use kar rahe hain taaki spaces ka issue na ho
    c.execute("UPDATE users SET password_hash = ? WHERE username LIKE 'pradum%yadav'", (hashed_pw,))
    
    if c.rowcount > 0:
        print(f"Success! Password for 'pradum yadav' reset to: {new_password}")
    else:
        print("User 'pradum yadav' not found!")
        
    conn.commit()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
