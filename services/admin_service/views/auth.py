from flask import render_template, redirect, url_for, session, request, jsonify, current_app
from services.common.oauth import oauth
import os
import logging
import json

# 📌 로깅 설정
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def login():
    session.permanent = True  # 🔥 세션 유지
    state = os.urandom(24).hex()  # ✅ 새로운 state 생성
    session["oidc_state"] = state  # ✅ Flask 세션에 저장

    # ✅ Redis에도 저장 (state → session_id 매핑)
    redis_key = f"state:{state}"
    current_app.config['SESSION_REDIS'].setex(redis_key, 300, session.sid)  # 5분 TTL 설정

    logger.debug(f"🔍 [DEBUG] 생성된 OIDC State 값: {state} (Session ID: {session.sid})")

    return oauth.oidc.authorize_redirect(
        os.getenv("AUTHORIZE_REDIRECT_URL"),
        state=state
    )
def logout():
    session.pop('user', None)
    session.modified = True  # 🔥 세션 변경 사항 반영
    logger.info("✅ 로그아웃 처리 완료, 메인 화면으로 이동")

    return redirect(current_app.config['MAP_SERVICE_URL'])  # 메인 화면으로 이동


def role_check():
    user = session.get('user')
    user_groups = user.get('cognito:groups', [])

    if "admin" in user_groups:
        return redirect(url_for('admin_bp.admin_dashboard_route'))
    else:
        return redirect(current_app.config['MAP_SERVICE_URL'])


def authorize():
    logger.debug("🔍 [DEBUG] authorize() 호출됨")

    requested_state = request.args.get("state")
    redis_key = f"state:{requested_state}"

    # ✅ Redis에서 state → session_id 매핑값 가져오기
    session_id = current_app.config["SESSION_REDIS"].get(redis_key)

    if not session_id:
        logger.error("🚨 [ERROR] Redis에서 state 값을 찾을 수 없음.")
        return jsonify({"error": "Invalid state or session expired"}), 403

    session_id = session_id.decode()  # ✅ Redis에서 가져온 값은 bytes이므로 decode() 필요
    logger.debug(f"🔍 [DEBUG] Redis에서 찾은 세션 ID: {session_id}")

    session_data = current_app.config["SESSION_REDIS"].get(f"session:{session_id}")
    if not session_data:
        logger.error("🚨 [ERROR] Redis에서 세션 데이터를 찾을 수 없음.")
        return jsonify({"error": "Session data not found"}), 403

    session_data = json.loads(session_data.decode())  # JSON 데이터 파싱
    logger.debug(f"🔍 [DEBUG] Redis에서 찾은 세션 데이터: {session_data}")

    # ✅ OAuth 인증 요청
    token = oauth.oidc.authorize_access_token()
    logger.debug(f"✅ 받은 token 정보: {token}")

    session["user"] = token["userinfo"]
    logger.debug(f"✅ 받은 사용자 정보: {session['user']}")

    return role_check()