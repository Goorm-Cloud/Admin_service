from flask import render_template, redirect, url_for, session, request, jsonify
from services.common.oauth import oauth
import os
import logging
from config import SESSION_REDIS

# 📌 로깅 설정
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def login():
    session.permanent = True  # ✅ 세션을 지속 유지
    session.modified = True   # ✅ 세션 변경 사항 적용

    if 'oidc_state' in session:
        state = session['oidc_state']  # 기존 state 값 사용
    else:
        state = os.urandom(24).hex()  # 새로운 state 값 생성
        session['oidc_state'] = state  # ✅ Redis에 저장

    logger.debug(f"🔍 [DEBUG] 생성된 OIDC State 값: {state}")
    logger.debug(f"🆔 [DEBUG] 현재 세션 ID: {session.get('session_id')}")  # 현재 세션 ID 확인

    return oauth.oidc.authorize_redirect(
        os.getenv("AUTHORIZE_REDIRECT_URL"),
        state=state
    )

def logout():
    session.pop('user', None)
    logger.info("✅ 로그아웃 처리 완료, 메인 화면으로 이동")

    return redirect(current_app.config['MAP_SERVICE_URL']) #민승님 메인 화면으로 이동


def role_check():
    user = session.get('user')
    user_groups = user.get('cognito:groups', [])
    logger.debug(f"🔍 [DEBUG] 사용자 그룹: {user_groups}")

    if "admin" in user_groups:
        logger.info("✅ 관리자 계정 확인됨, 관리자 대시보드로 이동")
        return redirect(url_for('admin_bp.admin_dashboard_route'))
    else:
        logger.info("✅ 일반 사용자 확인됨, 메인 페이지로 이동")
        return redirect(current_app.config['MAP_SERVICE_URL'])


def authorize():
    print("🔍 [DEBUG] authorize() 호출됨")
    logger.debug(f"🆔 [DEBUG] 현재 세션 ID: {session.get('session_id')}")  # 현재 세션 ID 확인

    requested_state = request.args.get('state')

    # Redis에서 직접 세션 조회
    redis_key = f"{SESSION_KEY_PREFIX}{session.get('session_id')}"
    redis_data = SESSION_REDIS.get(redis_key)

    logger.debug(f"🔍 [DEBUG] Redis 데이터: {redis_data}")

    if redis_data:
        import json
        redis_data = json.loads(redis_data)
        stored_state = redis_data.get("oidc_state", None)
    else:
        stored_state = None

    logger.debug(f"🔍 [DEBUG] OAuth State 확인 | 요청 값: {requested_state} | 세션 값: {stored_state}")

    if stored_state is None:
        logger.error("🚨 [ERROR] Redis에서 세션을 찾을 수 없음. 세션이 만료되었거나 저장되지 않았을 가능성이 있음.")
        return jsonify({"error": "Session not found in Redis"}), 403

    if requested_state != stored_state:
        logger.warning("🚨 CSRF Warning! State 값이 일치하지 않음")
        return jsonify({"error": "CSRF Warning! State does not match."}), 403

    token = oauth.oidc.authorize_access_token()
    logger.debug(f"✅ 받은 토큰 정보: {token}")

    session['user'] = token['userinfo']  # ✅ 로그인 후 사용자 정보 Redis에 저장
    logger.info(f"✅ 로그인 성공! 사용자 정보: {session['user']}")

    return role_check()
