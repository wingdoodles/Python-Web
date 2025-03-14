from flask import Blueprint

monitoring = Blueprint('monitoring', __name__, url_prefix='/system')

from monitoring import routes
