from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
    UserMixin,
)
from forms import RegistrationForm, LoginForm, TaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
from dotenv import load_dotenv
import os
from flask_migrate import Migrate



load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = 'FLASK_KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)


# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    description = db.Column(db.String(300), nullable=False)
    due_date = db.Column(db.DateTime, nullable=True)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for session tasks



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# (Run this once)
# @app.before_request
# def create_tables():
#     db.create_all()



def get_session_tasks():
    return session.get('tasks', [])


def save_session_tasks(tasks):
    session['tasks'] = tasks


def add_session_task(description, due_date):
    tasks = get_session_tasks()
    task = {
        'uuid': str(uuid.uuid4()),
        'description': description,
        'due_date': due_date.strftime('%m-%d-%Y %H:%M') if due_date else None,
        'completed': False
    }
    tasks.append(task)
    save_session_tasks(tasks)


def update_session_task(uuid, **kwargs):
    tasks = get_session_tasks()
    for task in tasks:
        if task['uuid'] == uuid:
            task.update(kwargs)
            break
    save_session_tasks(tasks)


def delete_session_task(uuid):
    tasks = get_session_tasks()
    tasks = [task for task in tasks if task['uuid'] != uuid]
    save_session_tasks(tasks)


def transfer_session_tasks_to_db(user):
    session_tasks = get_session_tasks()
    for task in session_tasks:
        new_task = Task(
            uuid=task['uuid'],
            description=task['description'],
            due_date=datetime.strptime(task['due_date'], '%m-%d-%Y %H:%M') if task['due_date'] else None,
            completed=task['completed'],
            owner=user
        )
        db.session.add(new_task)
    db.session.commit()
    session.pop('tasks', None)  # Clear session tasks after transferring



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        # Transfer session tasks to user account
        if 'tasks' in session:
            transfer_session_tasks_to_db(user)
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            # Transfer session tasks to user account
            if 'tasks' in session:
                transfer_session_tasks_to_db(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



@app.route('/', methods=['GET', 'POST'])
def index():
    form = TaskForm()
    if form.validate_on_submit():
        description = form.description.data
        due_date = form.due_date.data
        if current_user.is_authenticated:
            task = Task(
                description=description,
                due_date=due_date,
                owner=current_user
            )
            db.session.add(task)
            db.session.commit()
            flash('Task added!', 'success')
        else:
            add_session_task(description, due_date)
            flash('Task added to your session!', 'success')
        return redirect(url_for('index'))


    if current_user.is_authenticated:
        todo_tasks = Task.query.filter_by(owner=current_user, completed=False).order_by(Task.due_date).all()
        completed_tasks = Task.query.filter_by(owner=current_user, completed=True).order_by(Task.due_date).all()
    else:
        session_tasks = get_session_tasks()
        todo_tasks = [task for task in session_tasks if not task['completed']]
        completed_tasks = [task for task in session_tasks if task['completed']]

    return render_template('index.html', form=form, todo_tasks=todo_tasks, completed_tasks=completed_tasks,
                           authenticated=current_user.is_authenticated)



@app.route('/complete/<string:task_uuid>', methods=['POST'])
def complete_task(task_uuid):
    if current_user.is_authenticated:
        task = Task.query.filter_by(uuid=task_uuid, owner=current_user).first()
        if not task:
            flash('Task not found or unauthorized.', 'danger')
            return redirect(url_for('index'))
        task.completed = True
        db.session.commit()
        flash('Task marked as complete!', 'success')
    else:
        tasks = get_session_tasks()
        for task in tasks:
            if task['uuid'] == task_uuid:
                task['completed'] = True
                break
        save_session_tasks(tasks)
        flash('Task marked as complete in your session!', 'success')
    return redirect(url_for('index'))



@app.route('/delete/<string:task_uuid>', methods=['POST'])
def delete_task(task_uuid):
    if current_user.is_authenticated:
        task = Task.query.filter_by(uuid=task_uuid, owner=current_user).first()
        if not task:
            flash('Task not found or unauthorized.', 'danger')
            return redirect(url_for('index'))
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted!', 'success')
    else:
        delete_session_task(task_uuid)
        flash('Task deleted from your session!', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, port=5002)
