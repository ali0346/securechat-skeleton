# """MySQL users table + salted hashing (no chat storage).""" 
# raise NotImplementedError("students: implement DB layer")

"""MySQL users table + salted hashing (no chat storage)."""

import os
import sys
import pymysql
import pymysql.cursors
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database configuration
DB_HOST = os.getenv('DB_HOST', '127.0.0.1')
DB_PORT = int(os.getenv('DB_PORT', 3306))
DB_USER = os.getenv('DB_USER')
DB_PASS = os.getenv('DB_PASS')
DB_NAME = os.getenv('DB_NAME')

if not all([DB_USER, DB_PASS, DB_NAME]):
    print("Error: DB_USER, DB_PASS, and DB_NAME must be set in .env file", file=sys.stderr)
    sys.exit(1)

def get_db_conn() -> pymysql.connections.Connection:
    """Establishes a connection to the MySQL database."""
    try:
        connection = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )
        return connection
    except pymysql.Error as e:
        print(f"Error connecting to MySQL: {e}", file=sys.stderr)
        sys.exit(1)

def create_tables(conn: pymysql.connections.Connection):
    """Creates the necessary tables in the database."""
    # Per Req 2.2 / PDF Page 7
    create_users_table_query = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    try:
        with conn.cursor() as cursor:
            cursor.execute(create_users_table_query)
        print("Tables created successfully.")
    except pymysql.Error as e:
        print(f"Error creating tables: {e}", file=sys.stderr)

# --- Functions to be used by the server ---

def create_user(conn: pymysql.connections.Connection, email: str, username: str, salt: bytes, pwd_hash: str) -> bool:
    """
    Inserts a new user into the database.
    Returns True on success, False on failure (e.g., duplicate email/username).
    """
    sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, (email, username, salt, pwd_hash))
        return True
    except pymysql.IntegrityError:
        # This handles duplicate email/username
        return False
    except pymysql.Error as e:
        print(f"Error creating user: {e}", file=sys.stderr)
        return False

def get_user_by_email(conn: pymysql.connections.Connection, email: str) -> dict | None:
    """Fetches a user by their email address."""
    sql = "SELECT email, username, salt, pwd_hash FROM users WHERE email = %s"
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, (email,))
            result = cursor.fetchone()
            return result
    except pymysql.Error as e:
        print(f"Error fetching user: {e}", file=sys.stderr)
        return None

# --- Main block to initialize DB ---

def main():
    """Main function to handle command-line arguments."""
    # Check for '--init' flag
    if len(sys.argv) > 1 and sys.argv[1] == '--init':
        print(f"Connecting to database '{DB_NAME}' at {DB_HOST}:{DB_PORT}...")
        try:
            conn = get_db_conn()
            with conn:
                create_tables(conn)
        except Exception as e:
            print(f"Database initialization failed: {e}", file=sys.stderr)
    else:
        print("Usage: python -m app.storage.db --init", file=sys.stderr)

if __name__ == "__main__":
    main()