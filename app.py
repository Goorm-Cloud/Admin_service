import os
from flask import Flask, url_for, jsonify
from services.common.models import db, migrate
from services.common.oauth import oauth
from dotenv import load_dotenv
from flask_session import Session
import redis

from services.admin_service.routes import admin_bp, login_bp

# .env 파일 자동 로드
load_dotenv()

def create_app():
    app = Flask(__name__)

    # config 설정파일 불러오기 *jinwoo
    app.config.from_pyfile('config.py')
    app.secret_key = os.urandom(24)

    # 📌 세션 설정
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_KEY_PREFIX'] = 'admin_service:'
    app.config['SESSION_REDIS'] = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))

    Session(app)

    # 📌 KAKAO API KEY 로드
    if not os.getenv("KAKAO_API_KEY"):
        raise ValueError("❌ KAKAO_API_KEY가 설정되지 않았습니다! .env 파일을 확인하세요.")
    app.config['TEMPLATES_AUTO_RELOAD'] = True

    # 📌 OAuth 설정
    oauth.init_app(app)
    oauth.register(
        name='oidc',
        authority='https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_HroMsatHG',
        client_id='77g5eu474omofv1t6ss848gn9u',
        client_secret=os.getenv("CLIENT_SECRET"),
        server_metadata_url='https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_HroMsatHG/.well-known/openid-configuration',
        client_kwargs={'scope': 'phone openid email'}
    )

    # 📌 DB 설정
    db.init_app(app)
    migrate.init_app(app, db)

    @app.route("/")
    def index():
        from flask import redirect
        return redirect("/admin")

    @app.route('/health')
    def health_check():
        return jsonify({"status": "healthy"}), 200

    # 📌 블루프린트 등록
    app.register_blueprint(login_bp)
    app.register_blueprint(admin_bp, url_prefix=app.config['ADMIN_SERVICE_URL'])
    # app.register_blueprint(map_bp, url_prefix=app.config['MAP_SERVICE_URL'])
    # app.register_blueprint(reservation_bp, url_prefix=app.config['RESERVATION_SERVICE_URL'])
    # app.register_blueprint(parkinglot_bp, url_prefix=app.config['PARKINGLOT_SERVICE_URL'])
    # app.register_blueprint(reservation_detail_bp, url_prefix=app.config['RESERVATION_DETAIL_SERVICE_URL'])

    return app

# Create the application instance
app = create_app()
