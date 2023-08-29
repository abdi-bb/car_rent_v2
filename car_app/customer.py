import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from car_app.db import get_db

bp = Blueprint('customer', __name__, url_prefix='/customer')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        last_name = request.form['last_name']
        address = request.form['address']
        phone_number = request.form['phone_number']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not name:
            error = 'Name is required.'
        elif not last_name:
            error = 'Last Name is required.'
        elif not address:
            error = 'Address is required.'
        elif not phone_number:
            error = 'Phone Number is required.'
        elif not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO customer (username, name, last_name, address, phone_number, email,  password) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (username, name, last_name, address, phone_number, email, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("customer.login"))

        flash(error)

    return render_template('customer/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        customer = db.execute(
            'SELECT * FROM customer WHERE username = ?', (username,)
        ).fetchone()

        if customer is None:
            error = 'Incorrect username.'
        elif not check_password_hash(customer['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['customer_id'] = customer['id']
            return redirect(url_for('car.index'))

        flash(error)

    return render_template('customer/login.html')

@bp.before_app_request
def load_logged_in_customer():
    customer_id = session.get('customer_id')

    if customer_id is None:
        g.customer = None
    else:
        g.customer = get_db().execute(
            'SELECT * FROM customer WHERE id = ?', (customer_id,)
        ).fetchone()

# logging out
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('customer.login'))

# Views that ask for login
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.customer is None:
            return redirect(url_for('customer.login'))

        return view(**kwargs)

    return wrapped_view