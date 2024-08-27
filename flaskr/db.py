import sqlite3

import click
from flask import current_app
from flask import g


def get_db():
    """Connect to the application's configured database. The connection
    is unique for each request and will be reused if this is called
    again.
    """
    if "db" not in g: # g is a special object, unique for each request. It's used to store data that might be accesed by multiple functions during the request. Connection stored and reused.
        g.db = sqlite3.connect( # 'sqlite3.connect' establishes a connection to the file pointed at by the DATABASE config key.This file doesn't have to exist yet.
            current_app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES
            # 'current_app' special object that points to the Flask app handling the request. 'get_db' will be called when the app's been created and is handling a request.
        )
        g.db.row_factory = sqlite3.Row #'sqlite3.Row' tells the connection to return rows that behave like dicts. It allows accessing the columns by name.

    return g.db


def close_db(e=None): # checks if a connection was created by checking if 'g.db' was set. If connection exists, it is closed. 
    """If this request connected to the database, close the
    connection.
    """
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():  #returns a database connection, used it to execute the commands read from file
    """Clear existing data and create new tables."""
    db = get_db()

    with current_app.open_resource("schema.sql") as f: # opens a file relative to 'flaskr' package
        db.executescript(f.read().decode("utf8"))


@click.command("init-db") #defines a command line command called 'init-db' that calls the 'init-db' function and shows a success message to the user.
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    click.echo("Initialized the database.")


def init_app(app):
    """Register database functions with the Flask app. This is called by
    the application factory.
    """
    app.teardown_appcontext(close_db) #tells Flask to call the function when cleaning up after returning the response. 
    app.cli.add_command(init_db_command) #adds a new command that can be called with the 'flask' command.
