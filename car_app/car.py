from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash, generate_password_hash

from car_app.customer import login_required
from car_app.db import get_db

bp = Blueprint('car', __name__)

# Car list
@bp.route('/')
@login_required
def index():
    db = get_db()
    cars = db.execute(
        'SELECT name, image'
        ' FROM car'
        ' ORDER BY name ASC'
    ).fetchall()
    return render_template('car/index.html', cars=cars)

# Guest mode page, Customer can see without logging in if he wish
@bp.route('/guest_mode')
def guest_mode():
    db = get_db()
    cars = db.execute(
        'SELECT name, image'
        ' FROM car'
        ' ORDER BY name ASC'
    ).fetchall()
    return render_template('car/index.html', cars=cars)
