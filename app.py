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

# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt token is picked from cookiesx
        # return 401 if token is not passed
        token = request.cookies.get('x-auth-token')
        if not token:
            return jsonify({'message' : 'Missing Token required authentication'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except:
            return jsonify({'message' : 'Invalid Token, try logging in again'}), 401
        # returns the current logged in users context to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated

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

@app.route('/logout', methods =['GET'])
@token_required
def logout(current_user):
    response = make_response(jsonify({'message' : 'User logged out'}), 200)
    response.delete_cookie('x-auth-token')
    return response
    
@app.route('/upload', methods =['POST'])
@token_required
def upload_pics(current_user):
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

        picture = Picture(
            user_id = current_user.public_id,
            pic_name = filename,
            pic_disc = disc,
            is_public = ispublic
        )

        # insert picture
        db.session.add(picture)
        db.session.commit()
    
        # return 200 if file is Uploaded Succesfully
        return jsonify({'message' : 'Uploaded Succesfully'}), 200

@app.route('/delete', methods = ['POST'])
@token_required
def delete_picture(current_user):
    data = request.form

    picture_id = data.get('pic_id')

    if not picture_id:
        return jsonify({'message' : 'Please enter a picture ID'}), 400
    
    pic = Picture.query\
        .filter(Picture.id == picture_id)\
        .first()
    
    if not pic:
        return jsonify({'message' : 'No Image to delete'}), 200
    
    # Delete selected picture
    db.session.delete(pic)
    db.session.commit()

    return jsonify({'message' : 'Image deleted'}), 200

@app.route('/update', methods = ['POST'])
@token_required
def update_picture(current_user):
    data = request.form

    picture_id = data.get('pic_id')
    update_disc = data.get('new_disc')

    if not picture_id or not update_disc:
        return jsonify({'message' : 'Please enter valid ID and description'}), 400
    
    pic = Picture.query\
        .filter(Picture.id == picture_id)\
        .first()
    
    if not pic:
        return jsonify({'message' : 'No Image to update'}), 200

    pic.pic_disc = update_disc
    db.session.commit()

    return jsonify({'message' : 'Image description updated'}), 200

@app.route('/home', methods =['GET'])
@token_required
def home(current_user):
    public = Picture.query\
        .filter(Picture.is_public == True)\
        .all()
    
    private = Picture.query\
        .filter(Picture.user_id == current_user.public_id)\
        .filter(Picture.is_public == False)\
        .all()

    all_pic = public + private 
    if not all_pic:
        # return 200 if no public images
        return jsonify({'message' : 'No Images'}), 200
    else:
        data = []
        for pic in all_pic:
            data.append({
                'pic_name' : pic.pic_name,
                'disc' : pic.pic_disc
            })
        # return 200 with all public images
        return jsonify({'pictures' : data}), 200

@app.route('/guest', methods =['GET'])
def get_public():
    public = Picture.query\
        .filter(Picture.is_public == True)\
        .all()

    if not public:
        # return 200 if no public images
        return jsonify({'message' : 'No Images'}), 200
    else:
        data = []
        for pic in public:
            data.append({
                'pic_name' : pic.pic_name,
                'disc' : pic.pic_disc
            })
        # return 200 with all public images
        return jsonify({'pictures' : data}), 200
    

@app.errorhandler(404)
def page_not_found(error):
    return jsonify({'message' : 'Page not available'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'message' : 'Method not allowed'}), 405

@app.errorhandler(500)
def server_error(error):
    return jsonify({'message' : 'Internal server error'}), 500

if __name__ == '__main__':
    app.run()
