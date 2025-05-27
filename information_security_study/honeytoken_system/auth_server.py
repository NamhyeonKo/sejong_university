# auth_server.py

from flask import Flask, request, jsonify
import jwt
import uuid
from datetime import datetime, timedelta, timezone
import time
import requests # Resource Server에 알림을 보내기 위함

from config import (
    JWT_SECRET, ACCESS_TOKEN_LIFESPAN_SECONDS, REFRESH_TOKEN_LIFESPAN_SECONDS,
    AUTH_SERVER_PORT, RESOURCE_SERVER_PORT, DB_PATH, RESOURCE_SERVER_HOST
)
import sqlite3 # issued_tokens_audit 용

app = Flask(__name__)

# 사용자 정보 (간단한 인메모리 저장소)
USERS = {'alice': 'password123'}

# Refresh Token 저장소 (인메 μόνο 메모리)
# { refresh_token_value: {'username': 'user1', 'expires_at': timestamp, 'last_access_token': 'prev_at_string'} }
REFRESH_TOKENS = {}

def log_issued_token(token, username, expires_at_dt, token_type='access'):
    """발급된 토큰을 감사용 테이블에 기록"""
    conn = None  # conn 변수를 None으로 초기화
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO issued_tokens_audit (token, username, issued_at, expires_at, type) VALUES (?, ?, ?, ?, ?)",
            (token, username, time.time(), expires_at_dt.timestamp(), token_type)
        )
        conn.commit()
    except Exception as e:
        print(f"Error logging issued token: {e}")
    finally:
        if conn:  # conn이 None이 아닐 경우에만 close 호출
            conn.close()

# ... (파일의 나머지 부분은 동일하게 유지) ...

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.form
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if username in USERS:
        return jsonify({"error": "User already exists"}), 400
    USERS[username] = password
    return jsonify({"message": f"User {username} registered successfully"}), 201

@app.route('/auth/token', methods=['POST'])
def issue_token():
    username = request.form.get('username')
    password = request.form.get('password')

    if USERS.get(username) != password:
        return jsonify(message="Invalid credentials"), 401

    # Access Token 생성
    access_token_issued_at = datetime.now(timezone.utc)
    access_token_expires_at = access_token_issued_at + timedelta(seconds=ACCESS_TOKEN_LIFESPAN_SECONDS)
    access_token_payload = {
        'sub': username,
        'iat': access_token_issued_at,
        'exp': access_token_expires_at,
        'type': 'access'
    }
    access_token = jwt.encode(access_token_payload, JWT_SECRET, algorithm='HS256')

    # Refresh Token 생성
    refresh_token_issued_at = datetime.now(timezone.utc)
    refresh_token_expires_at_ts = (refresh_token_issued_at + timedelta(seconds=REFRESH_TOKEN_LIFESPAN_SECONDS)).timestamp()
    refresh_token = str(uuid.uuid4())

    REFRESH_TOKENS[refresh_token] = {
        'username': username,
        'expires_at': refresh_token_expires_at_ts,
        'last_access_token': access_token # 현재 발급된 AT를 "이전 AT"로 저장
    }
    
    log_issued_token(access_token, username, access_token_expires_at, 'access')
    # Refresh token도 감사 로그에 남길 수 있음 (선택 사항)

    print(f"[AuthServer] Issued tokens for {username}. AT expires at {access_token_expires_at}")
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer',
        'expires_in': ACCESS_TOKEN_LIFESPAN_SECONDS
    })

@app.route('/auth/refresh', methods=['POST'])
def refresh_access_token():
    refresh_token_value = request.form.get('refresh_token')
    if not refresh_token_value:
        return jsonify(message="Refresh token required"), 400

    refresh_token_data = REFRESH_TOKENS.get(refresh_token_value)

    if not refresh_token_data or refresh_token_data['expires_at'] < time.time():
        if refresh_token_value in REFRESH_TOKENS: # 만료된 경우 삭제
            del REFRESH_TOKENS[refresh_token_value]
        return jsonify(message="Invalid or expired refresh token"), 401

    username = refresh_token_data['username']
    old_access_token_to_honeytokenize = refresh_token_data['last_access_token']

    # 새 Access Token 생성
    access_token_issued_at = datetime.now(timezone.utc)
    access_token_expires_at = access_token_issued_at + timedelta(seconds=ACCESS_TOKEN_LIFESPAN_SECONDS)
    new_access_token_payload = {
        'sub': username,
        'iat': access_token_issued_at,
        'exp': access_token_expires_at,
        'type': 'access'
    }
    new_access_token = jwt.encode(new_access_token_payload, JWT_SECRET, algorithm='HS256')

    # (선택적) 새 Refresh Token 발급 (보안 강화) - 여기서는 기존 RT를 유지하지 않고 새로 발급
    del REFRESH_TOKENS[refresh_token_value] # 이전 RT 무효화
    
    new_refresh_token_issued_at = datetime.now(timezone.utc)
    new_refresh_token_expires_at_ts = (new_refresh_token_issued_at + timedelta(seconds=REFRESH_TOKEN_LIFESPAN_SECONDS)).timestamp()
    new_refresh_token = str(uuid.uuid4())

    REFRESH_TOKENS[new_refresh_token] = {
        'username': username,
        'expires_at': new_refresh_token_expires_at_ts,
        'last_access_token': new_access_token # 새로 발급된 AT를 다음을 위한 "이전 AT"로 저장
    }
    
    log_issued_token(new_access_token, username, access_token_expires_at, 'access')

    # Resource Server에 이전 Access Token을 허니토큰으로 등록하도록 알림
    try:
        rs_url = f"http://{RESOURCE_SERVER_HOST}:{RESOURCE_SERVER_PORT}/internal/add_honeytoken"
        payload = {
            'token': old_access_token_to_honeytokenize,
            'username': username,
            'reason': 'superseded_by_refresh'
        }
        # 실제 운영 환경에서는 이 통신에 대한 보안(내부 인증 등) 필요
        response = requests.post(rs_url, data=payload, timeout=5)
        if response.status_code == 200:
            print(f"[AuthServer] Notified Resource Server to honeytokenize: {old_access_token_to_honeytokenize[:20]}...")
        else:
            print(f"[AuthServer] Failed to notify Resource Server: {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[AuthServer] Error notifying Resource Server: {e}")

    print(f"[AuthServer] Refreshed tokens for {username}. New AT expires at {access_token_expires_at}")
    return jsonify({
        'access_token': new_access_token,
        'refresh_token': new_refresh_token, # 새 RT 반환
        'token_type': 'bearer',
        'expires_in': ACCESS_TOKEN_LIFESPAN_SECONDS
    })

if __name__ == '__main__':
    # config에서 포트 정보 가져오기
    # from config import AUTH_SERVER_PORT # 이미 상단에 import 되어 있음
    print(f"Auth Server attempting to run on host 0.0.0.0, port {AUTH_SERVER_PORT}")
    app.run(host='0.0.0.0', port=AUTH_SERVER_PORT, debug=True)