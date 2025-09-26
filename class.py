from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask.views import MethodView
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import base64
import os
import json
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
# Config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'user-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'postgresql://postgres:welcome@localhost:5432/testdb'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------------------
# User Model
# ------------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)  # hashed
    password_plain = db.Column(db.String(200), nullable = False) #plain-text password

with app.app_context():
    #db.drop_all()
    db.create_all()

# ------------------------------
# Token Utils
# ------------------------------
def generate_token(user, hours=1):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=hours)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token if isinstance(token, str) else token.decode('utf-8')

def _b64url_decode(data: str) -> bytes:
    if isinstance(data, str):
        data = data.encode('utf-8')
    rem = len(data) % 4
    if rem:
        data += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(data)

def decode_jwt_unverified(token: str):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Token must have exactly 3 parts.')
    h_b64, p_b64, s_b64 = parts
    header = json.loads(_b64url_decode(h_b64))
    payload = json.loads(_b64url_decode(p_b64))
    return header, payload, s_b64

def _extract_token_from_request(req):
    auth = req.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth.split(' ', 1)[1].strip()
    if req.is_json:
        t = req.json.get('token')
        if t:
            return t.strip()
    t = req.args.get('token')
    if t:
        return t.strip()
    return None

# ------------------------------
# Class-Based APIs
# ------------------------------
class RegisterAPI(MethodView):
    def post(self):
        data = request.json or {}
        email = data.get('email')
        name = data.get('name')
        password = data.get('password')

        if not email or not name or not password:
            return jsonify({'message': 'Email, name and password are required'}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'User already exists'}), 409

        hashed = generate_password_hash(password)
        user = User(email=email, name=name, password=hashed, password_plain=password)
        db.session.add(user)
        db.session.commit()

        token = generate_token(user)
        return jsonify({'message': 'User registered successfully', 'token': token})


class LoginAPI(MethodView):
    def post(self):
        # Check for Bearer token
        auth = request.headers.get('Authorization', '')
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
            try:
                payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                return jsonify({'message': 'Login via token successful', 'payload': payload})
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token'}), 401

        # Fallback to email/password
        data = request.json or {}
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'message': 'Email and password are required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid credentials'}), 401

        token = generate_token(user)
        return jsonify({'message': 'Login successful', 'token': token})


class DecodeAPI(MethodView):
    def post(self):
        token = _extract_token_from_request(request)
        if not token:
            return jsonify({'message': 'No token provided'}), 400
        try:
            header, payload, signature_b64 = decode_jwt_unverified(token)
            return jsonify({
                'verified': False,
                'header': header,
                'payload': payload,
                'signature_b64url': signature_b64
            })
        except Exception as e:
            return jsonify({'message': 'Failed to decode token', 'error': str(e)}), 400


class VerifyAPI(MethodView):
    def post(self):
        token = _extract_token_from_request(request)
        if not token:
            return jsonify({'message': 'No token provided'}), 400
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            header = jwt.get_unverified_header(token)
            return jsonify({'verified': True, 'header': header, 'payload': payload})
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'message': 'Invalid token', 'error': str(e)}), 401


class UsersAPI(MethodView):
    def get(self):
        users = User.query.all()
        return jsonify([{'id': u.id, 'email': u.email, 'name': u.name} for u in users])

# ------------------------------
# Register Routes
# ------------------------------
app.add_url_rule('/register', view_func=RegisterAPI.as_view('register_api'))
app.add_url_rule('/login', view_func=LoginAPI.as_view('login_api'))
app.add_url_rule('/decode', view_func=DecodeAPI.as_view('decode_api'))
app.add_url_rule('/verify', view_func=VerifyAPI.as_view('verify_api'))
app.add_url_rule('/users', view_func=UsersAPI.as_view('users_api'))

# ------------------------------
# Run App
# ------------------------------
if __name__ == '__main__':
    app.run(debug=True, port=1100)
