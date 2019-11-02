# HERE WE CREATE THE BLUEPRINT THAT WILL SUPPORT THE ROUTE OF OUR AUTHENTICATION SERVICE

from flask import Blueprint

auth = Blueprint('auth', __name__)  # REMEMBER ('NAME_OF_BLUEPRINT', MODULE WHERE II IS LOCATED)

from . import views