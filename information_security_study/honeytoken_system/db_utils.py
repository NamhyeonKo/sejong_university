# db_utils.py (수정된 버전)

import sqlite3
import os
from config import DB_PATH

def init_db():
    """ 데이터베이스를 초기화하고 테이블 생성을 확인합니다. """
    conn = None # conn 초기화
    try:
        db_dir = os.path.dirname(DB_PATH)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            print(f"[DB Utils] Created directory: {db_dir}")

        print(f"[DB Utils] Attempting to connect to database at: {DB_PATH}")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        print("[DB Utils] Database connection successful.")

        # 테이블 생성 SQL 쿼리들
        tables_sql = [
            '''CREATE TABLE IF NOT EXISTS honeytokens (
                token TEXT PRIMARY KEY,
                username TEXT,
                registered_at TEXT,
                reason TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS honeytoken_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT,
                username TEXT,
                attempt_time TEXT,
                status TEXT,
                attacker_ip TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS issued_tokens_audit (
                token TEXT PRIMARY KEY,
                username TEXT,
                issued_at REAL,
                expires_at REAL,
                type TEXT DEFAULT 'access'
            )'''
        ]

        table_names = ["honeytokens", "honeytoken_logs", "issued_tokens_audit"]

        for i, sql in enumerate(tables_sql):
            cursor.execute(sql)
            print(f"[DB Utils] Executed: CREATE TABLE IF NOT EXISTS {table_names[i]}")

        conn.commit()
        print("[DB Utils] Database commit successful.")

        # 테이블 생성 확인 (선택적이지만 디버깅에 유용)
        print("[DB Utils] Verifying table creation...")
        for table_name in table_names:
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}';")
            if cursor.fetchone():
                print(f"[DB Utils] Table '{table_name}' verified.")
            else:
                print(f"[DB Utils] ERROR: Table '{table_name}' NOT FOUND after creation attempt!")
        
        print(f"[DB Utils] Database schema initialized successfully at {DB_PATH}")

    except sqlite3.Error as e:
        print(f"[DB Utils] SQLite error during DB initialization: {e}")
        # 오류 발생 시, 부분적으로 생성된 내용을 롤백할 수 있음 (connect 성공 시)
        if conn:
            conn.rollback()
        raise # 오류를 다시 발생시켜 db_init 컨테이너가 실패하도록 함
    except Exception as e:
        print(f"[DB Utils] Non-SQLite error during DB initialization: {e}")
        raise
    finally:
        if conn:
            conn.close()
            print("[DB Utils] Database connection closed.")

if __name__ == '__main__':
    print("[DB Utils] Initializing database via __main__...")
    try:
        init_db()
        print("[DB Utils] __main__: init_db() completed.")
    except Exception as e:
        print(f"[DB Utils] __main__: init_db() failed: {e}")
        # 실패 시 명시적으로 exit code를 0이 아닌 값으로 설정 (Docker Compose가 인지하도록)
        import sys
        sys.exit(1)