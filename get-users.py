import psycopg2
from init import connect


def main():
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users;")
    users = cur.fetchall()
    print(users)


if __name__ == "__main__":
    main()
