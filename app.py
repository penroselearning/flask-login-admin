from flask import Flask,render_template,request,url_for,redirect
from flask_sqlalchemy import SQLAlchemy

# New Import
from flask import flash
from flask_login import LoginManager,login_required, login_user,logout_user,current_user

from werkzeug.security import generate_password_hash, check_password_hash

from flask_admin import Admin,AdminIndexView
from flask_admin.contrib.sqla import ModelView


# init SQLAlchemy so we can use it later in our models


app = Flask(__name__)
db = SQLAlchemy(app)

app.config['SECRET_KEY'] = 'theloginapp'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#db.init_app(app)
    
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

from models import *
    
@login_manager.user_loader
def load_user(user_id):
# since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))

admin = Admin(app,index_view=MainAdminIndexView(),template_mode='bootstrap3')
admin.add_view(AllModelView(User,db.session))



@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user,remember=remember)
    return redirect(url_for('profile'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup',methods=['POST'])
def signup_post():

    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    # code to validate and add user to database goes here
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
def index():
    return render_template("index.html")

@app.route('/profile')
@login_required
def profile():
    return render_template("profile.html",name=current_user.name)

@app.route('/test')
@login_required
def test():
    return render_template("test.html")

@app.route('/new_test')
def new_test():
    return render_template("new_test.html")


if __name__ == '__main__':
    app.run(debug=True)
