from flask import (
    Blueprint, render_template, request, url_for, redirect, flash,    #se agrega flash para mostrar mensajes de error
    session, g                                                        #session es para manejar sesiones y g para almacenar datos de la aplicacion
    )

from werkzeug.security import generate_password_hash, check_password_hash

from .models import User
from todor import db

bp = Blueprint('auth', __name__, url_prefix='/auth') 

#Registro de usuario

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User(username, generate_password_hash(password))

        error = None

        user_name = User.query.filter_by(username=username).first()         #se busca el usuario en la base de datos filtrando por el nombre de usuario
        if user_name == None:
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('auth.login'))
        else:
            error = f'El usuario {username} ya registrado'

        flash(error)

    return render_template('auth/register.html')

#Login de usuario

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None
        #Validar los datos del usuario
        user_name = User.query.filter_by(username=username).first()         #se busca el usuario en la base de datos filtrando por el nombre de usuario
        if user_name == None:
            error = 'Usuario incorrecto'
        elif not check_password_hash(user_name.password, password):
            error = 'Contraseña incorrecta'

        #Iniciar sesion
        if error == None:
            session.clear()
            session['user_id'] = user_name.id
            db.session.commit()
            return redirect(url_for('todo.index'))

        flash(error)
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id == None:
        g.user = None
    else:
        g.user = User.query.get_or_404(user_id)

#Cerrar sesion
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

import functools

#Decorador para requerir login al navegar por la aplicacion
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user == None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view