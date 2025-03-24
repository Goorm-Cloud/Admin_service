from flask import render_template, redirect, url_for, session
from services.common.oauth import oauth
import os

# def login():
#     return oauth.oidc.authorize_redirect(os.getenv("AUTHORIZE_REDIRECT_URL"))

def login():
    state = os.urandom(24).hex()  # 랜덤한 상태 값 생성
    session['oidc_state'] = state  # ✅ Redis에 저장됨
    return oauth.oidc.authorize_redirect(
        os.getenv("AUTHORIZE_REDIRECT_URL"),
        state=state
    )

def logout():
    session.pop('user', None)
    return redirect(current_app.config['MAP_SERVICE_URL']) #민승님 메인 화면으로 이동


def role_check():
    user = session.get('user')
    user_groups = user.get('cognito:groups', [])

    if "admin" in user_groups:
        return redirect(url_for('admin_bp.admin_dashboard_route'))
    else:
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
    token = oauth.oidc.authorize_access_token()

    requested_state = request.args.get('state')
    stored_state = session.get('oidc_state')  # ✅ Redis에서 가져오기

    print(f"🔍 OAuth State 확인 | 요청 값: {state_in_request} | 세션 값: {state_in_session}")


    if requested_state != stored_state:
        return jsonify({"error": "CSRF Warning! State does not match."}), 403

    session['user'] = token['userinfo']  # ✅ 로그인 후 사용자 정보 Redis에 저장

    return role_check()


