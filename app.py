from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy 
from functools import wraps
from werkzeug.utils import secure_filename
import uuid
import bcrypt
import jwt
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '$3CR3T_K3Y'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['MAX_CONTENT_LENGTH'] = 25 * 1980 * 1080
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.jepg']
app.config['UPLOAD_PATH'] = 'Uploaded_Pictures'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(25))
    email = db.Column(db.String(50), unique = True)
    password = db.Column(db.String(50))

class Picture(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.String(50), db.ForeignKey('user.public_id'))
    pic_name = db.Column(db.String(50))
    pic_disc = db.Column(db.String(50))
    is_public = db.Column(db.Boolean, default = False, nullable = False)

def password_hash(password):
    # converting password to array of bytes 
    bytes = password.encode('utf-8') 
  
    # generating the salt 
    salt = bcrypt.gensalt() 
  
    # Hashing the password 
    hash = bcrypt.hashpw(bytes, salt) 
    return hash

def password_check(savedPassword, password):
    # encoding entered password
    userBytes = password.encode('utf-8')

    # checking password
    result = bcrypt.checkpw(userBytes, savedPassword)
    return result

#API for User SignUp
@app.route('/signup', methods =['POST'])
def signup():
    data = request.form
  
    # gets name, email and password
    name = data.get('name') 
    email = data.get('email')
    password = data.get('password')
  
    # checking for existing user
    user = User.query\
        .filter_by(email = email)\
        .first()

    if not user:
        # database ORM object
        user = User(
            public_id = str(uuid.uuid4()),
            name = name,
            email = email,
            password = password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()
  
        return make_response('Sign Up Successfully.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)

#API for User Login
@app.route('/login', methods =['POST'])
def login():
    auth = request.form
  
    if not auth or not auth.get('email') or not auth.get('password'):
        # returns 401 if any email or and password is missing
        return make_response(
            'Please enter valid Email and Password',
            401)
  
    user = User.query\
        .filter_by(email = auth.get('email'))\
        .first()

    if not user or password_check(user.password, auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({'public_id': user.public_id}, 
                           app.config['SECRET_KEY'])
        response = make_response(jsonify({'token' : token}), 201)
        response.set_cookie('x-auth-token', token)
        
        return response
    # returns 403 if password is wrong
    return make_response(
        'Account information entered is invalid',
        403)

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt token is picked from cookiesx
        # return 401 if token is not passed
        token = request.cookies.get('x-auth-token')
        if not token:
            return jsonify({'message' : 'Missing Token'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({'message' : 'Invalid Token'}), 401
        # returns the current logged in users context to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated
    
@token_required
@app.route('/upload', methods =['POST'])
def upload_pics():
    upload_pic = request.files['']
    data = request.form

    if not upload_pic:
        # return 400 if file not selected
        return jsonify({'message' : 'Select a file'}), 400
    
    if not data or not data.get('disc') or not data.get('ispublic'):
        # return 401 if discription and is_public is empty
        return jsonify({'message' : 'Select a file'}), 401
    
    disc = data.get('disc')
    ispublic = bool(int(data.get('ispublic')))

    filename = secure_filename(upload_pic.filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            # return 401 if wrong file extenstion is uploaded
            return jsonify({'message' : 'Invalid file type'}), 401
        
        upload_pic.save(os.path.join(app.config['UPLOAD_PATH'], filename))
        token = request.cookies.get('x-auth-token')
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
        current_user = User.query\
            .filter_by(public_id = data['public_id'])\
            .first()
        picture = Picture(
            user_id = current_user.public_id,
            pic_name = filename,
            pic_disc = disc,
            is_public = ispublic
        )

        # insert picture
        db.session.add(picture)
        db.session.commit()
    
        #return 200 if file is Uploaded Succesfully
        return jsonify({'message' : 'Uploaded Succesfully'}), 200


@app.route('/home', methods =['GET'])
@token_required
def get_all_users(current_user):

    return jsonify({"Text" : 'Hello, Welcome'})

if __name__ == '__main__':
    app.debug = True
    app.run()