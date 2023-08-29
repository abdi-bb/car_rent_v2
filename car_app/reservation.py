from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from car_app.customer import login_required
from car_app.db import get_db

bp = Blueprint('reservation', __name__)

@bp.route('/')
def index():
    db = get_db()
    reservations = db.execute(
        'SELECT p.id, title, body, created, author_id, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return render_template('reservation/index.html', reservations=reservations)