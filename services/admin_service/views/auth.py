from flask import render_template, redirect, url_for, session, request, jsonify, current_app
from services.common.oauth import oauth
import os
import logging
import json

# 📌 로깅 설정
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def login():
    session.permanent = True
    session.modified = True

    if 'oidc_state' in session:
        state = session['oidc_state']
    else:
        state = os.urandom(24).hex()
        session['oidc_state'] = state
        session.modified = True

    logger.debug(f"🔍 [DEBUG] 생성된 OIDC State 값: {state}")

    # ✅ Redis에 state 저장 (조회 용이하게)
    redis_key = f"state:{state}"
    current_app.config['SESSION_REDIS'].setex(redis_key, 300, session.sid)  # 5분 TTL

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
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        logger.warning("🚨 [WARNING] Refresh Token이 없음, 로그인 필요")
        return redirect(url_for('login'))

    user_id = get_user_id_from_token(refresh_token)
    user_session_key = f"{current_app.config['SESSION_KEY_PREFIX']}user:{user_id}"

    session_data = current_app.config['SESSION_REDIS'].get(user_session_key)

    if not session_data:
        logger.warning("🚨 [WARNING] Redis에서 사용자 세션을 찾을 수 없음.")
        return redirect(url_for('login'))

    session_data = json.loads(session_data)
    session['user'] = session_data["user_info"]

    user_groups = session['user'].get('cognito:groups', [])
    logger.debug(f"🔍 [DEBUG] 사용자 그룹: {user_groups}")

    if "admin" in user_groups:
        return redirect(url_for('admin_bp.admin_dashboard_route'))
    else:
        return redirect(current_app.config['MAP_SERVICE_URL'])


def authorize():
    logger.debug("🔍 [DEBUG] authorize() 호출됨")

    requested_state = request.args.get('state')

    # ✅ Redis에서 state 값으로 세션 ID 조회
    redis_key = f"state:{requested_state}"
    session_id = current_app.config['SESSION_REDIS'].get(redis_key)

    if not session_id:
        logger.error("🚨 [ERROR] Redis에서 state 값을 찾을 수 없음.")
        return jsonify({"error": "Invalid state or session expired"}), 403

    session_id = session_id.decode()
    logger.debug(f"🔍 [DEBUG] Redis에서 찾은 세션 ID: {session_id}")

    # ✅ Redis에서 실제 세션 데이터 조회
    session_key = f"session:{session_id}"
    session_data = current_app.config['SESSION_REDIS'].get(session_key)

    if not session_data:
        logger.error("🚨 [ERROR] Redis에서 세션 정보를 찾을 수 없음.")
        return jsonify({"error": "Session expired"}), 403

    session_data = json.loads(session_data)

    # 🔥 Authlib이 기대하는 state 값을 session에 강제로 설정
    session['oidc_state'] = requested_state

    # 🔥 인증 토큰 받아오기
    token = oauth.oidc.authorize_access_token()
    access_token = token.get("access_token")
    refresh_token = token.get("refresh_token")
    user_info = token.get("userinfo")

    if not user_info:
        return jsonify({"error": "User information not found"}), 403

    logger.debug(f"✅ 받은 사용자 정보: {user_info}")

    # 🔥 Redis에 사용자 세션 저장
    user_session_key = f"{current_app.config['SESSION_KEY_PREFIX']}user:{user_info.get('sub')}"
    session_data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_info": user_info
    }
    current_app.config['SESSION_REDIS'].setex(user_session_key, 86400, json.dumps(session_data))  # 24시간 유지

    # 🔥 Refresh Token을 HttpOnly Secure 쿠키로 설정
    response = role_check()
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=True,
        samesite="Lax"
    )

    return response