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
    state = os.urandom(24).hex()
    session["oidc_state"] = state

    redis_key = f"state:{state}"
    current_app.config['SESSION_REDIS'].setex(redis_key, 300, session.sid)

    # 🔥 Redis에 JSON 문자열로 저장
    session_data = json.dumps({"session_id": session.sid, "exp": 1711381200})
    current_app.config['SESSION_REDIS'].setex(f"session:{session.sid}", 300, session_data)

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
    requested_state = request.args.get("state")
    redis_key = f"state:{requested_state}"

    session_id = current_app.config["SESSION_REDIS"].get(redis_key)
    if not session_id:
        return jsonify({"error": "Invalid state or session expired"}), 403

    session_id = session_id.decode()
    session_data = current_app.config["SESSION_REDIS"].get(f"session:{session_id}")

    if not session_data:
        return jsonify({"error": "Session data not found"}), 403

    try:
        # 🔥 JSON으로 디코딩
        session_data = json.loads(session_data.decode())
        logger.debug(f"🔍 [DEBUG] Redis에서 찾은 세션 데이터 (JSON 변환 후): {session_data}")
    except Exception as e:
        return jsonify({"error": "Failed to decode session data"}), 500

    token = oauth.oidc.authorize_access_token()
    session["user"] = token["userinfo"]

    return role_check()