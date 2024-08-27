import functools

from flask import Blueprint
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from .db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth") # This creates a Blueprint named 'auth'. Like the application object, the blueprint needs to know where it’s defined, so __name__ is passed as the second argument. The url_prefix will be prepended to all the URLs associated with the blueprint.

# @bp.route('/index')
# def index():
#     return "Hello, World!"


def login_required(view):
    """View decorator that redirects anonymous users to the login page."""

    @functools.wraps(view) # This decorator returns a new view function that wraps the original view it's applied to.
    def wrapped_view(**kwargs): # It checks if a user is loaded and redirects to the login page otherwise. If is loaded the original view is called and continues normally.
        if g.user is None:
            return redirect(url_for("auth.login"))

        return view(**kwargs)

    return wrapped_view


@bp.before_app_request # register a function that runs before the view function, no matter what URL is requested.
def load_logged_in_user(): #checks if a user id is stored in the session, gets user's data from database, storing it on g.user
    """If a user id is stored in the session, load the user object from
    the database into ``g.user``."""
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = (
            get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()
        )

# Create first view: register
@bp.route("/register", methods=("GET", "POST")) # associates URL register with the register view function
def register(): 
    """Register a new user.

    Validates that the username is not already taken. Hashes the
    password for security.
    """
    if request.method == "POST": # if the user submitted the form, request.method will be POST. Start validating the input
        username = request.form["username"]  # request.form is a special type of dict mapping form keys and values.
        password = request.form["password"]
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
                    (username, generate_password_hash(password)), # generate_password used to securely hash the password and stored.
                )
                db.commit() # save the previous changes.
            except db.IntegrityError: # to assure that the username doesn't exist. Otherwise, a validation error is shown.
                # The username was already taken, which caused the
                # commit to fail. Show a validation error.
                error = f"User {username} is already registered."
            else:
                # Success, go to the login page.
                return redirect(url_for("auth.login")) # after storing the user, redirect to the login page.

        flash(error) # if validation fails, a error is shown. Flash messages can be retrieved when rendering a template.

    return render_template("/auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    """Log in a registered user by adding the user id to the session."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        error = None
        user = db.execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone() # fetchone() returns one row from the query. If the query returns no results, it returns None.

        if user is None:
            error = "Incorrect username."
        elif not check_password_hash(user["password"], password): # hashes the submitted passwords and securly compares them.
            error = "Incorrect password."

        if error is None:
            # store the user id in a new session and return to the index
            session.clear()
            session["user_id"] = user["id"] # session is a dict that stores data. If validation succeeds, user's id is stored in a new session
            return redirect(url_for("index"))

        flash(error)

    return render_template("/auth/login.html")


@bp.route("/logout")
def logout():
    """Clear the current session, including the stored user id."""
    session.clear()
    return redirect(url_for("index"))


