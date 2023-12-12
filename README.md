# PicStack

## PicStack
Building a RESTful app where users can upload pictures using Flask

## Dev Team Members
    Ramya Sree Karanam
    Yashas Kantharaj

## Setup:
### Steps to run:
    python -m pipenv shell
    pip install -r requirement.txt
    python app.py
    hit localhost:5000


### Command for virtual env:

    python -m pipenv shell
    exit

### Dependencies:
    bcrypt
    Flask
    Flask-SQLAlchemy
    PyJWT

    install SQLLite for the database

## Project Details:

Flask routes:

    POST /signup:
    Registers a new user with the given username, email and password in the form payload.
    
    POST /login:
    Log in a user with the given email and password in the form payload. The response includes a JWT token that needs to be used for accessing the protected routes. JWT token is saved into cookies.
    
    GET /logout:
    logs out the user and removes the JWT token saved in the cookies.

    POST /upload
    Upload a file to the Uploaded_Pictures directory. This endpoint is protected and needs a JWT token in the cookies.
    
    POST /delete:
    Deletes an image with a given ID in the form payload. This endpoint is protected and needs a JWT token in the cookies.

    POST /update:
    Updates the image description for the provided image ID with the updated description in the form payload. This endpoint is protected and needs a JWT token in the cookies.
    
    GET /home:
    Returns all the public images of all users and private images of the authenticated user from the Picture table. This endpoint is protected and needs a JWT token in the cookies.
    
    GET /guest:
    Returns all the public images from the Picture table.
    
Database models:

    User: Columns having public_id, name, email and password.
    Picture: Columns having user_id, pic_name, pic_disc and is_public.

Function:

    Decorator token_requrired takes a JWT token from the saved cookies and returns the corresponding user if the token is valid and has not expired. 
    password_hash encodes and hashes the password provided by the user.
    password_check checks the hashed password from the database with the password provided by the user while login.
