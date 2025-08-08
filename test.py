import string
import utils.encrypt as encrypt
from datetime import datetime, timedelta
from repository import password_repo

print(password_repo.generate_password_string(16, True, True))