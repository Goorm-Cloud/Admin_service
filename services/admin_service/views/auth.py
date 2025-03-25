from flask import render_template, redirect, url_for, session, request, jsonify, current_app
from services.common.oauth import oauth
import os
import logging
import json

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
        session.modified = True  # 🔥 세션 변경 사항 반영

    logger.debug(f"🔍 [DEBUG] 생성된 OIDC State 값: {state}")
    logger.debug(f"🆔 [DEBUG] 현재 세션 ID: {session.sid}")  # 현재 세션 ID 확인

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
    if not user:
        logger.warning("🚨 [WARNING] 사용자 정보가 없음, 로그인 페이지로 이동")
        return redirect(url_for('login'))

    user_groups = user.get('cognito:groups', [])
    logger.debug(f"🔍 [DEBUG] 사용자 그룹: {user_groups}")

    if "admin" in user_groups:
        logger.info("✅ 관리자 계정 확인됨, 관리자 대시보드로 이동")
        return redirect(url_for('admin_bp.admin_dashboard_route'))
    else:
        logger.info("✅ 일반 사용자 확인됨, 메인 페이지로 이동")
        return redirect(current_app.config['MAP_SERVICE_URL'])

def authorize():
    logger.debug("🔍 [DEBUG] authorize() 호출됨")
    logger.debug(f"🆔 [DEBUG] 현재 세션 ID: {session.sid}")  # 현재 세션 ID 확인

    requested_state = request.args.get('state')

    # 🔥 Redis에서 세션 데이터 가져오기
    redis_key = f"{current_app.config['SESSION_KEY_PREFIX']}{session.sid}"
    redis_data = current_app.config['SESSION_REDIS'].get(redis_key)

    if redis_data:
        # 🔥 Redis에서 가져온 데이터가 `bytes` 타입일 가능성 고려하여 문자열로 변환
        redis_data = json.loads(redis_data.decode('utf-8'))
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

    # 🔥 인증 토큰 받아오기
    token = oauth.oidc.authorize_access_token()
    logger.debug(f"✅ 받은 토큰 정보: {token}")

    # 🔥 사용자 정보 세션에 저장
    session['user'] = token['userinfo']
    session.modified = True  # ✅ 변경 사항 반영
    logger.info(f"✅ 로그인 성공! 사용자 정보: {session['user']}")

    return role_check()