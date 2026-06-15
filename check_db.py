import sqlite3

conn = sqlite3.connect('phishing_detector.db')
cur = conn.cursor()

# List all tables
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cur.fetchall()
print("=== TABLES ===")
for t in tables:
    print(t[0])

print("\n=== USERS ===")
try:
    cur.execute("SELECT id, username, email, role FROM users")
    for r in cur.fetchall():
        print(f"  ID:{r[0]}  Username:{r[1]}  Email:{r[2]}  Role:{r[3]}")
except Exception as e:
    print("users table:", e)
    try:
        cur.execute("SELECT id, username, email, role FROM user")
        for r in cur.fetchall():
            print(f"  ID:{r[0]}  Username:{r[1]}  Email:{r[2]}  Role:{r[3]}")
    except Exception as e2:
        print("user table:", e2)

conn.close()
