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