from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash, generate_password_hash

from car_app.customer import login_required
from car_app.db import get_db

bp = Blueprint('reservation', __name__)

@bp.route('/')
@login_required
def index():
    db = get_db()
    reservations = db.execute(
        'SELECT r.id, cu.name, pickup_time, ca.name'
        ' FROM reservation r'
        ' JOIN customer cu ON r.customer_id = cu.id'
        ' JOIN car ca on r.car_id = ca.id'
        ' ORDER BY pickup_time ASC'
    ).fetchall()
    return render_template('reservation/index.html', reservations=reservations)

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        error = None

        if not email:
            error = 'Email is required.'
        if not password:
            error = 'Password is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'INSERT INTO reservation (email, password, customer_id)'
                ' VALUES (?, ?, ?)',
                (email, generate_password_hash(password), g.customer['id'])
            )
            db.commit()
            return redirect(url_for('reservation.index'))

    return render_template('reservation/create.html')

def get_booking(id, check_author=True):
    booking = get_db().execute(
        'SELECT p.id, title, body, created, author_id, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' WHERE reservation.id = ?',
        (id,)
    ).fetchone()

    if post is None:
        abort(404, f"Post id {id} doesn't exist.")

    if check_author and post['author_id'] != g.user['id']:
        abort(403)

    return post
