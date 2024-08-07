from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy() #crea la base de datos

def create_app():

    app = Flask(__name__)

    #Configuracion del proyecto
    app.config.from_mapping(
        DEBUG=False,
        SECRET_KEY='28315387',
        SQLALCHEMY_DATABASE_URI = "sqlite:///todolist.db" #aqui se pone el nombre de la base de datos
    )

    db.init_app(app)

    #REGISTRO DE BLUEPRINTS
    from . import todo
    app.register_blueprint(todo.bp)

    from . import auth
    app.register_blueprint(auth.bp)

    @app.route('/')
    def index():
        return render_template('index.html')
    
    with app.app_context(): #crea la base de datos
        db.create_all()
    
    return app