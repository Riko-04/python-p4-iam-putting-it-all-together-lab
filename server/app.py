from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from config import db, bcrypt
from models import User, Recipe

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    bio = data.get('bio')
    image_url = data.get('image_url')

    if not username:
        return jsonify({"error": "Username is required"}), 422
    
    try:
        user = User(username=username, bio=bio, image_url=image_url)
        user.password_hash = password
        db.session.add(user)
        db.session.commit()
        return jsonify(user.to_dict()), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username must be unique"}), 422

@app.route('/check_session', methods=['GET'])
def check_session():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    user = User.query.get(user_id)
    return jsonify(user.to_dict())

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.authenticate(username, password)

    if user:
        session['user_id'] = user.id
        return jsonify(user.to_dict())
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout', methods=['DELETE'])
def logout():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    session.pop('user_id')
    return '', 204

@app.route('/recipes', methods=['GET', 'POST'])
def recipes():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == 'GET':
        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return jsonify([recipe.to_dict() for recipe in recipes]), 200

    if request.method == 'POST':
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if len(instructions) < 50:
            return jsonify({"error": "Instructions must be at least 50 characters long"}), 422

        try:
            recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete, user_id=user_id)
            db.session.add(recipe)
            db.session.commit()
            return jsonify(recipe.to_dict()), 201
        except IntegrityError:
            db.session.rollback()
            return jsonify({"error": "Invalid recipe data"}), 422

if __name__ == '__main__':
    app.secret_key = b'a\xdb\xd2\x13\x93\xc1\xe9\x97\xef2\xe3\x004U\xd1Z'
    app.run(debug=True)
