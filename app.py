import os

from flask import Flask, url_for, jsonify
from services.common.models import db, migrate
from services.common.oauth import oauth

from services.admin_service.routes import admin_bp, login_bp
# from services.map_service.routes import map_bp
# from services.reservation_service.routes import parkinglot_bp
# from services.reservation_service.reservation_route import reservation_bp
# # from services.reservation_detail_service.routes import reservation_detail_bp


def create_app():
    app = Flask(__name__)
    
    # Load configuration from environment variables
    app.config.update(
        ADMIN_SERVICE_URL=os.getenv('ADMIN_SERVICE_URL', '/admin'),
        SECRET_KEY=os.getenv('SECRET_KEY', os.urandom(24)),
        # Add other config variables as needed
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False
    )

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
