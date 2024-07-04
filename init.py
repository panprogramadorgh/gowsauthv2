# script de inicializacion de base de datos postgre

import psycopg2


def connect():
    try:
        # Conexion en modo desarrollo
        conn = psycopg2.connect(
            dbname="gowsauthv2",
            user="postgres",
            password="root",
            host="192.168.1.2",
            port="5432",
        )
        return conn
    except Exception as error:
        raise Exception(f"There has an error connecting to database: {error}")


def main():
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("""DROP TABLE IF EXISTS messages;""")
    cursor.execute("""DROP TABLE IF EXISTS users;""")
    cursor.execute(
        """
                   CREATE TABLE users (
                     user_id SERIAL NOT NULL PRIMARY KEY,
                     username VARCHAR(32) NOT NULL UNIQUE,
                     password VARCHAR(255) NOT NULL,
                     firstname VARCHAR(32) NOT NULL,
                     lastname VARCHAR(32) NOT NULL,
                     admin BOOLEAN NOT NULL DEFAULT FALSE
                   );
                   """
    )
    cursor.execute(
        """
                   CREATE TABLE messages (
                     message_id SERIAL NOT NULL PRIMARY KEY,
                     owner INT NOT NULL,
                     message TEXT NOT NULL,
                     FOREIGN KEY (owner) REFERENCES users (user_id) ON DELETE CASCADE
                   );
                   """
    )

    cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

    cursor.execute(
        """
        INSERT INTO users (username, password, firstname, lastname, admin) VALUES (%s, crypt('pass1', gen_salt('bf')), %s, %s, %s);
    """,
        ("user1", "paco", "sanz", True),
    )

    cursor.execute(
        """
                   SELECT * FROM users WHERE username = 'user1'
                   """
    )
    users = cursor.fetchall()

    user_id = users[0][0]

    cursor.execute(
        """
                INSERT INTO messages (owner, message) VALUES (%s, %s);
                """,
        (user_id, "hello world"),
    )

    conn.commit()

    cursor.execute(
        """
                   SELECT * FROM messages;
                   """
    )
    messages = cursor.fetchall()

    print(users)
    print(messages)


if __name__ == "__main__":
    main()
