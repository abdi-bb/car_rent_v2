from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort
from werkzeug.security import check_password_hash, generate_password_hash

from car_app.customer import login_required
from car_app.db import get_db

bp = Blueprint('booking', __name__, url_prefix='/booking')

# Booking index page(The logged in user can see his reservation)
@bp.route('/')
@login_required
def index():
    db = get_db()
    boookings = db.execute(
        'SELECT r.id, cu.name, pickup_time, ca.name'
        ' FROM reservation r'
        ' JOIN customer cu ON r.customer_id = cu.id'
        ' JOIN car ca on r.car_id = ca.id'
        ' ORDER BY pickup_time ASC'
    ).fetchall()
    return render_template('booking/index.html', boookings=boookings)

# The logged in user can make new booking
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
                'INSERT INTO booking (email, password, customer_id)'
                ' VALUES (?, ?, ?)',
                (email, generate_password_hash(password), g.customer['id'])
            )
            db.commit()
            return redirect(url_for('booking.index'))

    return render_template('booking/create.html')

# Getting booking with the same booking id
def get_booking(id, check_author=True):
    booking = get_db().execute(
        'SELECT r.id, cu.name, pickup_time, ca.name'
        ' FROM reservation r'
        ' JOIN customer cu ON r.customer_id = cu.id'
        ' JOIN car ca on r.car_id = ca.id'
        ' WHERE booking.id = ?',
        (id,)
    ).fetchone()

    if booking is None:
        abort(404, f"Booking id {id} doesn't exist.")

    if check_author and booking['customer_id'] != g.customer['id']:
        abort(403)

    return booking

@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    booking = get_booking(id)

    if request.method == 'POST':
        pickup_time = request.form['pickup_time']
        dropoff_time = request.form['dropoff_time']
        email = request.form['email']
        password = request.form['password']
        error = None

        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE booking SET pickup_time = ?, dropoff_time = ?, email = ?, password = ?'
                ' WHERE id = ?',
                (pickup_time, dropoff_time, email, password, id)
            )
            db.commit()
            return redirect(url_for('booking.index'))

    return render_template('booking/update.html', booking=booking)

@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_booking(id)
    db = get_db()
    db.execute('DELETE FROM booking WHERE id = ?', (id,))
    db.commit()
    return redirect(url_for('blog.index'))