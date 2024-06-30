


from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow import Schema, fields
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost:3306/fileparse'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'confidntial'
db = SQLAlchemy(app)
ma = Marshmallow(app)

class Userstc(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    username = db.Column(db.String(30), unique=True, nullable=False)
    _password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)

    @property
    def password(self):
        raise AttributeError("Password is not readable")
        
    @password.setter
    def password(self, password):
        self._password = generate_password_hash(password)

    def verify_pass(self, password):
        return check_password_hash(self._password, password)
        
class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str()
    username = fields.Str()
    email = fields.Str()

user_schema = UserSchema()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('currentuser')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        if TokenBlacklist.query.filter_by(token=token).first():
            return jsonify({'message': 'Login to access'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Userstc.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if Userstc.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
    
    if Userstc.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400
    
    if len(data["name"]) < 2:
        return jsonify({'message': 'First name must be greater than 1 character.'}), 400
    
    if len(data["password"]) < 7:
        return jsonify({'message': 'Password must be at least 7 characters.'}), 400
    
    user = Userstc(
        name=data['name'],
        username=data['username'],
        password=data['password'],
        email=data['email']
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    credentials = request.get_json()
    user = Userstc.query.filter_by(username=credentials["username"]).first()
    
    if not user or not user.verify_pass(credentials["password"]):
        return jsonify({'message': 'Invalid username or password'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(minutes=10)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    response = jsonify({'token': token})
    response.set_cookie("currentuser", token, httponly=True, secure=False) 
    return response

@app.route("/logout", methods=['POST'])
@token_required
def logout(current_user):
    token = request.cookies.get("currentuser")
    if token:
        blacklist_token = TokenBlacklist(token=token, blacklisted_on=datetime.utcnow())
        db.session.add(blacklist_token)
        db.session.commit()
    response = make_response(jsonify({'message': 'Logout successful'}))
    response.delete_cookie('currentuser')
    return response

@app.route('/', methods=['GET'])
@token_required
def home(current_user):
    return jsonify({'message': f'Assalamualaikum {current_user.name}'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
