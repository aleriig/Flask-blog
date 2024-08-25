import functools
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth') # This creates a Blueprint named 'auth'. Like the application object, the blueprint needs to know where it’s defined, so __name__ is passed as the second argument. The url_prefix will be prepended to all the URLs associated with the blueprint.

# Create first view: register
@bp.route('/register', methods=('GET', 'POST')) # associates URL register with the register view function
def register():
    if request.method == 'POST': # if the user submitted the form, request.method will be POST. Start validating the input
        username = request.form['username'] # request.form is a special type of dict mapping form keys and values.
        password = request.form['password']
        db = get_db()
        error = None
        
        if not username: # Validate that username and password are not empty.
            error = "Username is required."
        elif not password:
            error = "Password is required."
        
        if error is None:
            try:
                db.execute( # SQL query with ? placeholders for any user input. Tuple of values to replace the placeholders.Database take care of escaping the values so you are not vulnerable to a SQL injections.
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)) # generate_password used to securely hash the password and stored.
                )
                db.commit() # save the previous changes.
            except db.IntegrityError: # to assure that the username doesn't exist. Otherwise, a validation error is shown.
                error = f'User {username} is already registered.'
            else:
                return redirect(url_for('auth.login')) # after storing the user, redirect to the login page.
        
        flash(error) # if validation fails, a error is shown. Flash messages can be retrieved when rendering a template.
    
    return render_template('/auth/register.html')

@bp.route('/login', method=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username)
        ).fetchone() # fetchone() returns one row from the query. If the query returns no results, it returns None.
        
        if user is None:
            error = "Incorrect username"
        elif not check_password_hash(user['password'], password): # hashes the submitted passwords and securly compares them.
            error = "Incorrect password"
        
        if error is None:
            session.clear()
            session['user_id'] = user['id'] # session is a dict that stores data. If validation succeeds, user's id is stored in a new session
            return redirect(url_for('index'))
        
        flash(error)
    
    return render_template('/auth/login.html')

@bp.before_app_request # register a function that runs before the view function, no matter what URL is requested.
def load_logged_in_user(): #checks if a user id is stored in the session, gets user's data from database, storing it on g.user
    user_id = session.get('user_id')
    
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view) # This decorator returns a new view function that wraps the original view it's applied to.
    def wrapped_view(**kwargs): # It checks if a user is loaded and redirects to the login page otherwise. If is loaded the original view is called and continues normally.
        if g.user is None:
            return redirect(url_for('auth.login')) 
        # url_for() generates the URL to a view based on a name and arguments. The name associated is also called the 'endpoint', and by default it's the same as the name of the view function. 
        # When using a blueprint, the name of the blueprint is prepended to the name of the function, so the endpoint for the 'login' function is 'auth.login' because you added it to the 'auth' blueprint.

        return view(**kwargs)
    return wrapped_view