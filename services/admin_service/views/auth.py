from flask import render_template, redirect, url_for, session
from services.common.oauth import oauth
import os

def login():
    return oauth.oidc.authorize_redirect(os.getenv("AUTHORIZE_REDIRECT_URL"))

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


def authorize():
    print("🔍 [DEBUG] authorize() 호출됨")
    token = oauth.oidc.authorize_access_token()
    print("토큰 정보: ", token)
    user = token['userinfo']
    session['user'] = user

    return role_check()


