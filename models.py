from app import db
from flask import redirect,url_for,request
from flask_login import UserMixin,current_user,login_user,logout_user
from flask_admin import Admin,AdminIndexView
from flask_admin.contrib.sqla import ModelView

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

class AllModelView(ModelView):

    can_delete = False
    page_size = 50
    # can_create = False
    # can_edit = False
    # can_delete = False
    # column_searchable_list = ['name', 'email']
    # column_filters = ['country']
    # column_editable_list = ['name', 'last_name'] # for inline editing
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self,name,**kwargs):
        return redirect(url_for('login'),next=request.url)

class MainAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated
    
    def inaccessible_callback(self,name,**kwargs):
        return redirect(url_for('login'),next=request.url)
