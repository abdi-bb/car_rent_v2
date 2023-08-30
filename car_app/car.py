from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash, generate_password_hash

from car_app.customer import login_required
from car_app.db import get_db

bp = Blueprint('car', __name__)

# Temporary Car index page(The logged in customer can see main car list)
@bp.route('/')
@login_required
def index():
    return render_template('car/index.html')