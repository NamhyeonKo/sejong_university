# config.py (변경 없음 - Docker Compose에서 환경 변수로 주입할 것이므로)
import os

JWT_SECRET = os.getenv('JWT_SECRET', 'your-jwt-super-secret-key-dev')
ACCESS_TOKEN_LIFESPAN_SECONDS = int(os.getenv('ACCESS_TOKEN_LIFESPAN_SECONDS', 30))
REFRESH_TOKEN_LIFESPAN_SECONDS = int(os.getenv('REFRESH_TOKEN_LIFESPAN_SECONDS', 300))
DB_PATH = os.getenv('DB_PATH', '/app/db_data/honey_tokens_multi.db') # 컨테이너 내 경로 유지

# Docker Compose에서 서비스 이름으로 주입될 예정. 로컬 실행 시 'localhost' 사용.
AUTH_SERVER_HOST = os.getenv('AUTH_SERVER_HOST', 'localhost')
RESOURCE_SERVER_HOST = os.getenv('RESOURCE_SERVER_HOST', 'localhost')
# 클라이언트 웹 앱 자체는 localhost로 접근하므로 HOST 설정 불필요

AUTH_SERVER_PORT = int(os.getenv('AUTH_SERVER_PORT', 5001))
RESOURCE_SERVER_PORT = int(os.getenv('RESOURCE_SERVER_PORT', 5002))
CLIENT_WEB_APP_PORT = int(os.getenv('CLIENT_WEB_APP_PORT', 5003))

CLIENT_REFRESH_THRESHOLD_RATIO = float(os.getenv('CLIENT_REFRESH_THRESHOLD_RATIO', 0.8))