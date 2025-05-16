from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from app.db import get_db

bp = Blueprint('gizmo', __name__)


@bp.route('/')
def index():
    return render_template('routes/index.html')