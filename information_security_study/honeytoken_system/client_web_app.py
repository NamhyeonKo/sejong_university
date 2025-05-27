# client_web_app.py

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import requests
import time
from datetime import datetime, timedelta, timezone
import os # <<<<<<<<<<<<<<<< 이 줄 추가

from config import (
    AUTH_SERVER_HOST, AUTH_SERVER_PORT,
    RESOURCE_SERVER_HOST, RESOURCE_SERVER_PORT,
    CLIENT_WEB_APP_PORT, ACCESS_TOKEN_LIFESPAN_SECONDS
)

AUTH_BASE_URL = f"http://{AUTH_SERVER_HOST}:{AUTH_SERVER_PORT}"
RESOURCE_BASE_URL = f"http://{RESOURCE_SERVER_HOST}:{RESOURCE_SERVER_PORT}"

app = Flask(__name__)
# app.secret_key = os.urandom(24) # 세션 관리를 위한 시크릿 키 -> __main__ 블록으로 이동 또는 여기서 유지

# 자동 재발급 시 실제 만료 시간보다 얼마나 일찍 재발급 시도할지 (초)
TOKEN_REFRESH_SAFETY_MARGIN_SECONDS = 5


@app.route('/')
def home():
    token_info = {
        'access_token': session.get('access_token'),
        'refresh_token': session.get('refresh_token'),
        'expires_at_iso': session.get('expires_at_iso'),
        'access_token_lifespan': ACCESS_TOKEN_LIFESPAN_SECONDS, # JS 타이머용
        'safety_margin': TOKEN_REFRESH_SAFETY_MARGIN_SECONDS # JS 타이머용
    }
    return render_template('client_ui.html', token_info=token_info)

@app.route('/login', methods=['POST'])
def login_action():
    username = request.form.get('username')
    password = request.form.get('password')
    
    try:
        response = requests.post(f"{AUTH_BASE_URL}/auth/token", data={'username': username, 'password': password})
        response.raise_for_status()
        token_data = response.json()

        session['access_token'] = token_data['access_token']
        session['refresh_token'] = token_data['refresh_token']
        
        expires_in = token_data.get('expires_in', ACCESS_TOKEN_LIFESPAN_SECONDS)
        expires_at_utc = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        session['expires_at_iso'] = expires_at_utc.isoformat()
        
        flash('Login successful!', 'success')
    except requests.exceptions.HTTPError as e:
        error_msg = "Login failed."
        if e.response is not None:
            try:
                error_detail = e.response.json().get('message', e.response.text)
                error_msg += f" Server says: {error_detail}"
            except ValueError: # JSON 디코딩 실패
                error_msg += f" Server response: {e.response.text}"
        else:
            error_msg += f" Error: {e}"
        flash(error_msg, 'error')
    except requests.exceptions.RequestException as e:
        flash(f'Login request error: {e}', 'error')
        
    return redirect(url_for('home'))

@app.route('/js_auto_refresh', methods=['POST'])
def js_auto_refresh():
    """JavaScript에 의해 호출되어 백그라운드에서 토큰을 재발급하는 엔드포인트"""
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        return jsonify({"error": "No refresh token in session"}), 400

    try:
        print("[ClientWebApp] Attempting auto token refresh via JS call...")
        response = requests.post(f"{AUTH_BASE_URL}/auth/refresh", data={'refresh_token': refresh_token})
        response.raise_for_status()
        new_token_data = response.json()

        session['access_token'] = new_token_data['access_token']
        if 'refresh_token' in new_token_data: # 새 Refresh Token이 발급된 경우 업데이트
             session['refresh_token'] = new_token_data['refresh_token']

        expires_in = new_token_data.get('expires_in', ACCESS_TOKEN_LIFESPAN_SECONDS)
        expires_at_utc = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        session['expires_at_iso'] = expires_at_utc.isoformat()
        
        print(f"[ClientWebApp] Auto refresh successful. New AT expires at: {session['expires_at_iso']}")
        return jsonify({
            "message": "Token refreshed successfully",
            "access_token": session['access_token'],
            "refresh_token": session.get('refresh_token'), # 업데이트된 RT 전달
            "expires_in": expires_in,
            "expires_at_iso": session['expires_at_iso']
        }), 200

    except requests.exceptions.HTTPError as e:
        error_msg = "Auto refresh failed."
        session.clear() # 재발급 실패 시 세션 클리어하고 재로그인 유도
        if e.response is not None:
            try:
                error_detail = e.response.json().get('message', e.response.text)
                error_msg += f" Server says: {error_detail}"
            except ValueError:
                error_msg += f" Server response: {e.response.text}"
        else:
            error_msg += f" Error: {e}"
        print(f"[ClientWebApp] {error_msg}")
        return jsonify({"error": error_msg, "force_logout": True}), e.response.status_code if e.response is not None else 500
    except requests.exceptions.RequestException as e:
        print(f"[ClientWebApp] Auto refresh request error: {e}")
        return jsonify({"error": f"Auto refresh request error: {e}", "force_logout": True}), 500


@app.route('/access_resource', methods=['POST'])
def resource_action():
    access_token = session.get('access_token')
    # 사용자가 직접 입력한 토큰이 있다면 그것을 우선 사용 (허니토큰 테스트용)
    manual_token = request.form.get('manual_token')
    token_to_use = manual_token if manual_token else access_token

    if not token_to_use:
        flash('No access token available. Please login.', 'error')
        return redirect(url_for('home'))

    headers = {'Authorization': f'Bearer {token_to_use}'}
    api_message = ""
    try:
        print(f"[ClientWebApp] Accessing resource with token: {token_to_use[:20]}...")
        response = requests.get(f"{RESOURCE_BASE_URL}/resource", headers=headers)
        # HTTP 상태 코드에 관계없이 응답 내용을 보려고 시도
        if response.status_code == 200:
            api_message = response.json().get('message', 'Successfully accessed resource, but no message found.')
            flash(api_message, 'success')
        else:
            try:
                error_detail = response.json().get('message', response.text)
            except ValueError:
                error_detail = response.text
            api_message = f"Failed to access resource. Status: {response.status_code}. Server says: {error_detail}"
            flash(api_message, 'error')
            if response.status_code == 401 and "Access token expired" in error_detail:
                 # 이 경우는 JS 자동 재발급이 실패했거나 타이밍 문제일 수 있음.
                 # 수동 재발급을 유도하거나, UI에서 재시도 알림.
                 flash("Access token might be expired. Try refreshing or re-logging in.", "warning")


    except requests.exceptions.RequestException as e:
        api_message = f'Resource request error: {e}'
        flash(api_message, 'error')
    
    session['last_api_message'] = api_message # 결과를 세션에 저장하여 home에서 표시
    return redirect(url_for('home'))

@app.route('/logout')
def logout_action():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    # 디렉토리 구조에 맞게 templates 폴더 지정
    # import os # 이미 파일 상단에 import 되어 있음
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    
    # app = Flask(__name__, template_folder=template_dir) # app은 이미 전역으로 정의됨
    # app.secret_key = os.urandom(24) # Flask 세션 암호화용 시크릿 키
    
    # Flask app 인스턴스를 __main__ 블록 내에서 재정의하지 않고,
    # 전역 app 인스턴스의 설정을 여기서 하거나, 전역에서 한 번만 설정합니다.
    # 여기서는 전역 app 인스턴스가 이미 생성되었으므로, 해당 인스턴스의 설정을 변경합니다.
    app.template_folder = template_dir
    if not app.secret_key: # 전역에서 secret_key가 설정되지 않았다면 여기서 설정
        app.secret_key = os.urandom(24)
    
    print(f"Client Web App attempting to run on host 0.0.0.0, port {CLIENT_WEB_APP_PORT}")
    app.run(host='0.0.0.0', port=CLIENT_WEB_APP_PORT, debug=True)
