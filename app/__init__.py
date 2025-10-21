
import os
from flask import Flask
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from dotenv import load_dotenv



load_dotenv()

mongo = PyMongo()
jwt = JWTManager()

def create_app():
    flask_app = Flask(__name__)

    flask_app.config['MONGO_URI'] = os.getenv('MONGO_URI')
    flask_app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

    CORS(flask_app, origin=["*"])

    @flask_app.route('/')
    def home():
        return "Hello, world!"

    mongo.init_app(flask_app)
    jwt.init_app(flask_app)

    from app.auth import auth as auth_blueprint
    flask_app.register_blueprint(auth_blueprint, url_prefix='/auth')


    # Check MongoDB connection
    try:
        with flask_app.app_context():
            mongo.db.command('ping')
            print(" Connected to MongoDB")
    except Exception as e:
        print(" Error connecting to MongoDB:", e)



    return flask_app

