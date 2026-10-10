"""Flask extension singletons.

Kept in their own module so models.py and the app factory can both import
`db` without a circular import.
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
