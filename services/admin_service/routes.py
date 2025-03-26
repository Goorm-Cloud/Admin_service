from flask import Blueprint
from .views.auth import login, role_check, authorize, logout
from .views.admin_list import admin_dashboard
from .views.reservation import add_reservation, edit_reservation, delete_reservation, reservation_detail
from .views.parkinglot import edit_parkinglot, admin_parkinglot


# bp 생성
login_bp = Blueprint('login_bp', __name__)
admin_bp = Blueprint('admin_bp', __name__)



# 로그인 관련 라우트
@login_bp.route('/login')
def login_route():
    return login()

@login_bp.route('/role_check')
def role_check_route():
    return role_check()

@login_bp.route('/authorize')
def authorize_route():
    return authorize()

@login_bp.route('/logout')
def logout_route():
    return logout()

@login_bp.route('/callback')
def callback_route():
    return authorize()

# 관리자 관련 라우트 - 예약 정보
@admin_bp.route('/')
def admin_dashboard_route():
    return admin_dashboard()

@admin_bp.route('/reservation/add', methods=['GET', 'POST'])
def add_reservation_route():
    return add_reservation()

@admin_bp.route('/reservation/edit/<int:reservation_id>', methods=['GET', 'POST'])
def edit_reservation_route(reservation_id):
    return edit_reservation(reservation_id)

@admin_bp.route('/reservation/delete/<int:reservation_id>', methods=['GET', 'POST'])
def delete_reservation_route(reservation_id):
    return delete_reservation(reservation_id)


@admin_bp.route('/reservation/<int:reservation_id>', methods=['GET'])
def reservation_detail_route(reservation_id):
    return reservation_detail(reservation_id)



# 관리자 관련 라우트 - 주차장 정보
@admin_bp.route('/parkinglot/edit/<int:parkinglot_id>', methods=['GET', 'POST'])
def edit_parkinglot_route(parkinglot_id):
    return edit_parkinglot(parkinglot_id)

@admin_bp.route('/parkinglot')
def admin_parkinglot_route():
    return admin_parkinglot()