import sqlite3
import bcrypt

# Crea el archivo
open("./database.db", "w")

conn = sqlite3.connect("./database.db")

conn.execute("BEGIN;")

conn.execute("""
DROP TABLE IF EXISTS users;
""")

conn.execute("""
CREATE TABLE users (
  user_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  firstname TEXT NOT NULL,
  lastname TEXT NOT NULL,
  admin INTEGER NOT NULL
);
""")

salt = bcrypt.gensalt(16)
hashed_password = bcrypt.hashpw(password=b"pass1", salt=salt).decode("utf-8")

conn.execute("""
INSERT INTO users (username, password, firstname, lastname, admin) VALUES (?, ?, ?, ?, ?);
""", ("user1", hashed_password, "paco", "sanz", 0))

conn.execute("""
COMMIT;
""")

cursor = conn.execute("""
                      SELECT * FROM users WHERE TRUE
                      """)
data = cursor.fetchall()
print(data)