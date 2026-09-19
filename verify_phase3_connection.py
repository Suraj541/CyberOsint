import os
import sys
from pathlib import Path

# Add paths
api_path = Path(r"c:\Users\suraj\Desktop\the_info\cyber-osint\apps\api")
root_path = Path(r"c:\Users\suraj\Desktop\the_info\cyber-osint")
sys.path.insert(0, str(api_path))
sys.path.insert(0, str(root_path))
os.environ["DATABASE_URL"] = "postgresql://postgres:postgres_secure_pass@127.0.0.1:5432/cyber_osint"
os.environ["USE_SQLITE_FALLBACK"] = "False"

import psycopg2
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

print("1. Testing raw psycopg2 connection...")
conn = psycopg2.connect("postgresql://postgres:postgres_secure_pass@127.0.0.1:5432/cyber_osint")
cur = conn.cursor()
cur.execute("SELECT version();")
ver = cur.fetchone()[0]
print("   psycopg2 connected successfully:", ver)
cur.close()
conn.close()

print("2. Testing SQLAlchemy engine and connection pool...")
engine = create_engine(os.environ["DATABASE_URL"], pool_size=5, max_overflow=10, pool_pre_ping=True)
with engine.connect() as connection:
    res = connection.execute(text("SELECT 1 AS alive"))
    assert res.scalar() == 1
    print("   SQLAlchemy engine connected successfully.")

print("3. Testing SessionLocal, transaction begin, commit, rollback...")
Session = sessionmaker(bind=engine)
session = Session()

# Create a temporary test table
session.execute(text("CREATE TEMP TABLE test_conn_probe (id SERIAL PRIMARY KEY, val TEXT);"))
session.commit()

# Insert and commit
session.execute(text("INSERT INTO test_conn_probe (val) VALUES ('commit_test');"))
session.commit()

res = session.execute(text("SELECT val FROM test_conn_probe WHERE val='commit_test';")).scalar()
assert res == "commit_test"
print("   Transaction commit verified.")

# Insert and rollback
session.execute(text("INSERT INTO test_conn_probe (val) VALUES ('rollback_test');"))
session.rollback()

res = session.execute(text("SELECT count(*) FROM test_conn_probe WHERE val='rollback_test';")).scalar()
assert res == 0
print("   Transaction rollback verified.")
session.close()

print("4. Testing app.database.check_database_connection()...")
from app.database import check_database_connection, engine as app_engine
print("   app.database.engine url:", app_engine.url)
assert "postgresql" in app_engine.url.drivername
is_alive = check_database_connection()
print("   check_database_connection():", is_alive)
assert is_alive

print("PHASE 3 CONNECTION TEST: ALL CHECKS PASSED!")
