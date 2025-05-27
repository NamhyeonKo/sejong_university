# resource_server.py

from flask import Flask, request, jsonify, render_template_string # render_template_string 추가
import jwt
import sqlite3
from datetime import datetime, timezone
import time

# config.py에서 필요한 설정값들을 가져옵니다.
# 실제 파일에서는 config.py가 같은 디렉토리에 있다고 가정합니다.
from config import JWT_SECRET, RESOURCE_SERVER_PORT, DB_PATH, CLIENT_WEB_APP_PORT

app = Flask(__name__)

# CLIENT_WEB_APP_PORT를 app.config에 설정하여 템플릿에서 사용 가능하게 합니다.
# 이 설정은 if __name__ == '__main__': 블록으로 옮겨도 좋습니다.
app.config["CLIENT_WEB_APP_PORT"] = CLIENT_WEB_APP_PORT

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

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
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
    except sqlite3.IntegrityError:
        if conn: conn.rollback()
        print(f"[ResourceServer] Honeytoken (IntegrityError) likely already exists: {token[:20]}...")
        return jsonify({"message": "Honeytoken likely already exists or other integrity error"}), 409
    except Exception as e:
        if conn: conn.rollback()
        print(f"[ResourceServer] Error adding honeytoken internally: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


def log_honeytoken_attempt(token_str, username, status, ip_address=None):
    conn = None
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
        if conn:
            conn.close()

@app.route('/resource', methods=['GET'])
def protected_resource():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify(message="Authorization header with Bearer token required"), 401

    token = auth_header.split(" ")[1]
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT username FROM honeytokens WHERE token = ?", (token,))
        honeytoken_entry = cursor.fetchone()

        if honeytoken_entry:
            username = honeytoken_entry['username']
            print(f"[ResourceServer] HONEYTOKEN DETECTED for user {username}: {token[:20]}...")
            log_honeytoken_attempt(token, username, "honeytoken_detected_at_resource (from_db)", request.remote_addr)
            return jsonify(message="Access Denied (Honeytoken Detected)"), 403

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = payload['sub']
            print(f"[ResourceServer] Valid token for user {username}. Access granted.")
            return jsonify(message=f"Hello {username}, this is the protected resource! Current time: {time.time()}")

        except jwt.ExpiredSignatureError:
            print(f"[ResourceServer] Expired token received: {token[:20]}...")
            expired_token_username = 'unknown_expired_user'
            try:
                unverified_payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_exp": False})
                expired_token_username = unverified_payload.get('sub', 'unknown_expired_user')
            except Exception:
                 pass

            cursor.execute("SELECT 1 FROM honeytokens WHERE token = ?", (token,))
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO honeytokens (token, username, registered_at, reason) VALUES (?, ?, ?, ?)",
                    (token, expired_token_username, datetime.now(timezone.utc).isoformat(), "expired_at_resource")
                )
                conn.commit()
                print(f"[ResourceServer] Expired token now registered as honeytoken: {token[:20]}...")
                log_honeytoken_attempt(token, expired_token_username, "honeytoken_registered (expired_at_resource)", request.remote_addr)
            else:
                log_honeytoken_attempt(token, expired_token_username, "honeytoken_detected (was_already_honeytoken_on_expiry)", request.remote_addr)
            return jsonify(message="Access token expired"), 401

        except jwt.InvalidTokenError as e:
            print(f"[ResourceServer] Invalid token: {e} - Token: {token[:20]}...")
            log_honeytoken_attempt(token, "unknown_invalid_user", f"invalid_token_at_resource ({type(e).__name__})", request.remote_addr)
            return jsonify(message=f"Invalid token: {e}"), 401
    
    except sqlite3.Error as db_err:
        print(f"[ResourceServer] Database error in protected_resource: {db_err}")
        return jsonify(message="Database error"), 500
    except Exception as e_global:
        print(f"[ResourceServer] Global error in protected_resource: {e_global}")
        return jsonify(message="An unexpected error occurred"), 500
    finally:
        if conn:
            conn.close()


@app.route('/debug/honeytokens', methods=['GET'])
def view_honeytokens():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT token, username, registered_at, reason FROM honeytokens ORDER BY registered_at DESC")
        tokens = cursor.fetchall()
        
        # CLIENT_WEB_APP_PORT를 config에서 가져와 링크에 사용
        client_app_port = app.config.get("CLIENT_WEB_APP_PORT", 5003)

        html = f"""
        <html><head><title>Registered Honeytokens</title>
        <style> table, th, td {{ border: 1px solid black; border-collapse: collapse; padding: 5px; font-family: sans-serif; }} 
        body {{font-family: sans-serif; margin: 20px;}} h2{{margin-bottom: 10px;}}
        a {{color: #007bff; text-decoration: none;}} a:hover {{text-decoration: underline;}}
        </style></head><body>
        <h2>Registered Honeytokens</h2>
        <table>
            <thead>
                <tr>
                    <th>Token</th>
                    <th>Username</th>
                    <th>Registered At (UTC)</th>
                    <th>Reason</th>
                </tr>
            </thead>
            <tbody>
        """
        for token_entry in tokens:
            html += f"""
                <tr>
                    <td>{token_entry['token'] if token_entry['token'] else ''}</td>
                    <td>{token_entry['username']}</td>
                    <td>{token_entry['registered_at']}</td>
                    <td>{token_entry['reason']}</td>
                </tr>
            """
        html += f"""
            </tbody>
        </table>
        <p><a href="/debug/honeytoken_logs">View Honeytoken Access Logs</a></p>
        <p><a href="http://localhost:{client_app_port}">Back to Client App</a></p>
        </body></html>
        """
        return render_template_string(html)

    except Exception as e:
        print(f"Error in view_honeytokens: {e}")
        return f"<h1>Error loading honeytokens</h1><p>{e}</p>", 500
    finally:
        if conn:
            conn.close()


@app.route('/debug/honeytoken_logs', methods=['GET'])
def view_honeytoken_logs():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, token, username, attempt_time, status, attacker_ip FROM honeytoken_logs ORDER BY attempt_time DESC")
        logs = cursor.fetchall()

        client_app_port = app.config.get("CLIENT_WEB_APP_PORT", 5003)

        html = f"""
        <html><head><title>Honeytoken Access Logs</title>
        <style> table, th, td {{ border: 1px solid black; border-collapse: collapse; padding: 5px; font-family: sans-serif; }} 
        body {{font-family: sans-serif; margin: 20px;}} h2{{margin-bottom: 10px;}}
        a {{color: #007bff; text-decoration: none;}} a:hover {{text-decoration: underline;}}
        </style></head><body>
        <h2>Honeytoken Access Logs</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Token</th>
                    <th>Username</th>
                    <th>Attempt Time (UTC)</th>
                    <th>Status</th>
                    <th>Attacker IP</th>
                </tr>
            </thead>
            <tbody>
        """
        for log_entry in logs:
            html += f"""
                <tr>
                    <td>{log_entry['id']}</td>
                    <td>{log_entry['token'] if log_entry['token'] else ''}</td>
                    <td>{log_entry['username']}</td>
                    <td>{log_entry['attempt_time']}</td>
                    <td>{log_entry['status']}</td>
                    <td>{log_entry['attacker_ip']}</td>
                </tr>
            """
        html += f"""
            </tbody>
        </table>
        <p><a href="/debug/honeytokens">View Registered Honeytokens</a></p>
        <p><a href="http://localhost:{client_app_port}">Back to Client App</a></p>
        </body></html>
        """
        return render_template_string(html)
        
    except Exception as e:
        print(f"Error in view_honeytoken_logs: {e}")
        return f"<h1>Error loading honeytoken logs</h1><p>{e}</p>", 500
    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    # CLIENT_WEB_APP_PORT를 app.config에 명시적으로 설정합니다.
    # 이는 render_template_string 내에서 f-string을 통해 사용될 수 없으므로,
    # app.config를 통해 접근하도록 합니다.
    # from config import CLIENT_WEB_APP_PORT # 이미 파일 상단에서 import됨
    # app.config["CLIENT_WEB_APP_PORT"] = CLIENT_WEB_APP_PORT 
    # -> 이미 파일 상단에서 app.config["CLIENT_WEB_APP_PORT"] = CLIENT_WEB_APP_PORT 로 설정했습니다.

    print(f"Resource Server attempting to run on host 0.0.0.0, port {RESOURCE_SERVER_PORT}")
    app.run(host='0.0.0.0', port=RESOURCE_SERVER_PORT, debug=True)