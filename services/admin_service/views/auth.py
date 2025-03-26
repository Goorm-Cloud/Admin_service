from flask import render_template, redirect, url_for, session, request, jsonify, current_app
from services.common.oauth import oauth
import os
import logging
import json

# 📌 로깅 설정
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def login():

    # state = os.urandom(24).hex()  # ✅ OIDC State 생성
    # logger.debug(f"✅ [DEBUG] state 생성: {state}")

    return oauth.oidc.authorize_redirect(os.getenv("AUTHORIZE_REDIRECT_URL"), state=state)


def authorize():
    """Cognito에서 리디렉션 후 호출되는 콜백 함수 (액세스 토큰 발급)"""

    # 1️⃣ ✅ `state` 및 `code` 검증
    requested_state = request.args.get("state")
    authorization_code = request.args.get("code")

    logger.debug(f"✅ 콜백 요청 - State: {requested_state}, Code: {authorization_code}")

    token = oauth.oidc.authorize_access_token()
    user = token['userinfo']
    session['user'] = user
    logger.debug(f"✅ [DEBUG] 받은 토큰 데이터: {token}")


    return redirect(url_for('admin_bp.admin_dashboard_route'))


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