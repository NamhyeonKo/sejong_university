# resource_server.py

from flask import Flask, request, jsonify
import jwt
import sqlite3
from datetime import datetime, timezone
import time

from config import JWT_SECRET, RESOURCE_SERVER_PORT, DB_PATH

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row # 결과를 딕셔너리처럼 접근 가능하게
    return conn

@app.route('/internal/add_honeytoken', methods=['POST'])
def add_honeytoken_internal():
    """ Auth Server가 호출하여 특정 토큰을 허니토큰으로 등록하는 내부 API """
    token = request.form.get('token')
    username = request.form.get('username')
    reason = request.form.get('reason', 'unknown_internal_request')

    if not token or not username:
        return jsonify({"error": "Token and username required"}), 400

    conn = None  # conn 변수를 None으로 초기화
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # 이미 등록된 허니토큰인지 확인 (중복 방지)
        cursor.execute("SELECT 1 FROM honeytokens WHERE token = ?", (token,))
        if cursor.fetchone():
            print(f"[ResourceServer] Honeytoken already exists: {token[:20]}...")
            return jsonify({"message": "Honeytoken already exists"}), 200

        cursor.execute(
            "INSERT INTO honeytokens (token, username, registered_at, reason) VALUES (?, ?, ?, ?)",
            (token, username, datetime.now(timezone.utc).isoformat(), reason)
        )
        conn.commit()
        print(f"[ResourceServer] Honeytoken added via internal API: {token[:20]}... by {username} (Reason: {reason})")
        return jsonify({"message": "Honeytoken added successfully"}), 200
    except sqlite3.IntegrityError: # 혹시 모를 중복 삽입 시도 (PRIMARY KEY 제약)
        if conn: conn.rollback() # conn이 할당되었을 경우에만 rollback
        print(f"[ResourceServer] Honeytoken (IntegrityError) likely already exists: {token[:20]}...")
        return jsonify({"message": "Honeytoken likely already exists or other integrity error"}), 409
    except Exception as e:
        if conn: conn.rollback() # conn이 할당되었을 경우에만 rollback
        print(f"[ResourceServer] Error adding honeytoken internally: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:  # conn이 None이 아닐 경우에만 close 호출
            conn.close()


def log_honeytoken_attempt(token_str, username, status, ip_address=None):
    conn = None  # conn 변수를 None으로 초기화
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO honeytoken_logs (token, username, attempt_time, status, attacker_ip) VALUES (?, ?, ?, ?, ?)",
            (token_str, username, datetime.now(timezone.utc).isoformat(), status, ip_address)
        )
        conn.commit()
    except Exception as e:
        print(f"Error logging honeytoken attempt: {e}")
    finally:
        if conn:  # conn이 None이 아닐 경우에만 close 호출
            conn.close()

@app.route('/resource', methods=['GET'])
def protected_resource():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify(message="Authorization header with Bearer token required"), 401

    token = auth_header.split(" ")[1]
    conn = None  # conn 변수를 None으로 초기화
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. 허니토큰 DB 조회
        cursor.execute("SELECT username FROM honeytokens WHERE token = ?", (token,))
        honeytoken_entry = cursor.fetchone()

        if honeytoken_entry:
            username = honeytoken_entry['username']
            print(f"[ResourceServer] HONEYTOKEN DETECTED for user {username}: {token[:20]}...")
            # conn을 여기서 닫지 않고 log_honeytoken_attempt 함수가 자체적으로 연결하도록 함
            log_honeytoken_attempt(token, username, "honeytoken_detected_at_resource (from_db)", request.remote_addr)
            # 실제로는 여기서 더 복잡한 디셉션 로직 (예: 가짜 데이터 반환, 특정 알림 발송) 수행 가능
            return jsonify(message="Access Denied (Honeytoken Detected)"), 403

        # 2. 허니토큰이 아니면 JWT 유효성 검사
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['sub']
            # 토큰이 유효하면 정상 처리
            print(f"[ResourceServer] Valid token for user {username}. Access granted.")
            return jsonify(message=f"Hello {username}, this is the protected resource! Current time: {time.time()}")

        except jwt.ExpiredSignatureError:
            # 만료된 토큰! -> 허니토큰으로 등록 (만약 아직 없다면)
            print(f"[ResourceServer] Expired token received: {token[:20]}...")
            expired_token_username = 'unknown_expired_user'
            try:
                unverified_payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})
                expired_token_username = unverified_payload.get('sub', 'unknown_expired_user')
            except Exception: # 디코딩 실패 시 기본 사용자 사용
                 pass


            # 중복 체크 후 허니토큰 추가 (conn은 아직 유효해야 함)
            cursor.execute("SELECT 1 FROM honeytokens WHERE token = ?", (token,)) # cursor 재사용
            if not cursor.fetchone():
                cursor.execute( # cursor 재사용
                    "INSERT INTO honeytokens (token, username, registered_at, reason) VALUES (?, ?, ?, ?)",
                    (token, expired_token_username, datetime.now(timezone.utc).isoformat(), "expired_at_resource")
                )
                conn.commit() # commit
                print(f"[ResourceServer] Expired token now registered as honeytoken: {token[:20]}...")
                log_honeytoken_attempt(token, expired_token_username, "honeytoken_registered (expired_at_resource)", request.remote_addr)
            else:
                log_honeytoken_attempt(token, expired_token_username, "honeytoken_detected (was_already_honeytoken_on_expiry)", request.remote_addr)
            return jsonify(message="Access token expired"), 401

        except jwt.InvalidTokenError as e:
            print(f"[ResourceServer] Invalid token: {e} - Token: {token[:20]}...")
            log_honeytoken_attempt(token, "unknown_invalid_user", f"invalid_token_at_resource ({type(e).__name__})", request.remote_addr)
            return jsonify(message=f"Invalid token: {e}"), 401
    
    except sqlite3.Error as db_err: # get_db_connection 실패 또는 DB 작업 중 오류
        print(f"[ResourceServer] Database error in protected_resource: {db_err}")
        return jsonify(message="Database error"), 500
    except Exception as e_global: # 기타 예외
        print(f"[ResourceServer] Global error in protected_resource: {e_global}")
        return jsonify(message="An unexpected error occurred"), 500
    finally:
        if conn:
            conn.close()


@app.route('/debug/honeytokens', methods=['GET'])
def view_honeytokens():
    conn = None # 초기화
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT token, username, registered_at, reason FROM honeytokens ORDER BY registered_at DESC")
        tokens = cursor.fetchall()
        return jsonify([dict(row) for row in tokens])
    except Exception as e:
        print(f"Error in view_honeytokens: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route('/debug/honeytoken_logs', methods=['GET'])
def view_honeytoken_logs():
    conn = None # 초기화
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, token, username, attempt_time, status, attacker_ip FROM honeytoken_logs ORDER BY attempt_time DESC")
        logs = cursor.fetchall()
        return jsonify([dict(row) for row in logs])
    except Exception as e:
        print(f"Error in view_honeytoken_logs: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # config에서 포트 정보 가져오기
    # from config import RESOURCE_SERVER_PORT # 이미 상단에 import 되어 있음
    print(f"Resource Server attempting to run on host 0.0.0.0, port {RESOURCE_SERVER_PORT}")
    app.run(host='0.0.0.0', port=RESOURCE_SERVER_PORT, debug=True)