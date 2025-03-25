from flask import render_template, redirect, url_for, session, request, jsonify, current_app
from services.common.oauth import oauth
import os
import logging
import json

# 📌 로깅 설정
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)



def login():
    """사용자 로그인 시, OIDC state와 session_id를 Redis에 저장하고 Cognito 인증 페이지로 리디렉션"""
    session.permanent = True
    state = os.urandom(24).hex()  # ✅ OIDC State 생성
    session["oidc_state"] = state

    session_id = session.sid  # 현재 Flask 세션 ID 가져오기
    redis_state_key = f"state:{state}"
    redis_session_key = f"session:{session_id}"

    # ✅ JSON 직렬화하여 Redis에 저장
    current_app.config["SESSION_REDIS"].setex(redis_state_key, 300, json.dumps(session_id))
    session_data = json.dumps({"session_id": session_id, "exp": 1711381200})
    current_app.config["SESSION_REDIS"].setex(redis_session_key, 300, session_data)

    logger.debug(f"✅ 로그인 요청 - State: {state}, Session ID: {session_id}")

    return oauth.oidc.authorize_redirect(
        os.getenv("AUTHORIZE_REDIRECT_URL"),
        state=state
    )



def authorize():
    """Cognito에서 리디렉션 후 호출되는 콜백 함수 (액세스 토큰 발급)"""

    # ✅ `state` 및 `code` 검증
    requested_state = request.args.get("state")
    authorization_code = request.args.get("code")

    if not requested_state:
        logger.error("🚨 [ERROR] 요청된 state 값이 없음! CSRF 검증 실패")
        return jsonify({"error": "State parameter missing"}), 400

    if not authorization_code:
        logger.error("🚨 [ERROR] Authorization code가 없음! 토큰 요청 불가.")
        return jsonify({"error": "Authorization code missing"}), 400

    logger.debug(f"✅ 콜백 요청 - State: {requested_state}, Code: {authorization_code}")

    # ✅ Cognito에 Authorization Code 전달하여 액세스 토큰 요청
    try:
        token = oauth.oidc.authorize_access_token()
        session["user"] = token["userinfo"]
        logger.debug(f"✅ [DEBUG] 받은 토큰 데이터: {token}")
    except Exception as e:
        logger.error(f"🚨 [ERROR] 토큰 요청 실패: {str(e)}")
        return jsonify({"error": "Failed to retrieve access token"}), 500

    return role_check()


def role_check():
    """사용자 그룹(role)에 따라 관리자 대시보드 또는 일반 페이지로 리디렉션"""
    user = session.get('user')
    user_groups = user.get('cognito:groups', [])

    if "admin" in user_groups:
        return redirect(url_for('admin_bp.admin_dashboard_route'))
    else:
        return redirect(current_app.config['MAP_SERVICE_URL'])


def logout():
    """사용자 로그아웃"""
    session.pop('user', None)
    session.modified = True  # 🔥 세션 변경 사항 반영
    logger.info("✅ 로그아웃 처리 완료, 메인 화면으로 이동")

    return redirect(current_app.config['MAP_SERVICE_URL'])  # 메인 화면으로 이동