from flask_login import UserMixin

ROLES = ['admin', 'user']

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
            
    def get_id(self):
        return str(self.id)
    
