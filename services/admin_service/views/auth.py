from flask import render_template, redirect, url_for, session, request
from services.common.oauth import oauth
import os
import logging

# 📌 로깅 설정
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# def login():
#     return oauth.oidc.authorize_redirect(os.getenv("AUTHORIZE_REDIRECT_URL"))

def login():
    state = os.urandom(24).hex()  # 랜덤한 상태 값 생성
    session['oidc_state'] = state  # ✅ Redis에 저장됨
    logger.debug(f"🔍 [DEBUG] 생성된 OIDC State 값: {state}")

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


# def authorize():
#     print("🔍 [DEBUG] authorize() 호출됨")
#     token = oauth.oidc.authorize_access_token()
#     print("✅ Received token: ", token)
#
#     state_in_request = request.args.get('state')
#     state_in_session = session.get('oauth_state')
#
#     print(f"🔍 OAuth State 확인 | 요청 값: {state_in_request} | 세션 값: {state_in_session}")
#
#     if state_in_request != state_in_session:
#         return "State mismatch error", 400
#
#     print("토큰 정보: ", token)
#     user = token['userinfo']
#     session['user'] = user
#
#     return role_check()

def authorize():
    print("🔍 [DEBUG] authorize() 호출됨")

    requested_state = request.args.get('state')
    stored_state = session.get('oidc_state')  # ✅ Redis에서 가져오기
    logger.debug(f"🔍 [DEBUG] OAuth State 확인 | 요청 값: {requested_state} | 세션 값: {stored_state}")

    if requested_state != stored_state:
        logger.warning("🚨 CSRF Warning! State 값이 일치하지 않음")
        return jsonify({"error": "CSRF Warning! State does not match."}), 403

    token = oauth.oidc.authorize_access_token()
    logger.debug(f"✅ 받은 토큰 정보: {token}")

    session['user'] = token['userinfo']  # ✅ 로그인 후 사용자 정보 Redis에 저장
    logger.info(f"✅ 로그인 성공! 사용자 정보: {session['user']}")


    return role_check()


