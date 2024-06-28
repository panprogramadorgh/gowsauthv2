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
             DROP TABLE IF EXISTS messages;
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

conn.execute("""
CREATE TABLE messages (
  message_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  owner INTEGER NOT NULL,
  message TEXT NOT NULL
);
""")

salt = bcrypt.gensalt(16)
hashed_password = bcrypt.hashpw(password=b"pass1", salt=salt).decode("utf-8")

conn.execute("""
INSERT INTO users (username, password, firstname, lastname, admin) VALUES (?, ?, ?, ?, ?);
""", ("user1", hashed_password, "paco", "sanz", 0))

cursor = conn.execute("""
             SELECT user_id FROM users WHERE username = "user1"
             """)

rows = cursor.fetchall()
user_id = rows[0][0]

conn.execute("""
             INSERT INTO messages (owner, message) VALUES (?, ?)
             """, (user_id, "hello world"))

conn.execute("""
COMMIT;
""")

# Mostrar todos los usuarios
cursor = conn.execute("""
                      SELECT * FROM users WHERE TRUE
                      """)
rows = cursor.fetchall()
print(rows)

# Mostrar los mensaje de user1 (paco)
cursor = conn.execute(f"""
                      SELECT * FROM messages WHERE owner = {user_id}
                      """)
rows = cursor.fetchall()
print(rows)