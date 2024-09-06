from flask import Flask, request, make_response, jsonify
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
from dotenv import load_dotenv
import os
import cloudinary
import cloudinary.uploader
import re

from models import db, User, Activity

app = Flask(__name__)
load_dotenv()
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES_DAYS')))
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES_DAYS')))

cloudinary.config( 
    cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'), 
    api_key = os.getenv('CLOUDINARY_API_KEY'), 
    api_secret = os.getenv('CLOUDINARY_API_SECRET'), 
    secure=True
)

migrate = Migrate(app, db)
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
api = Api(app)
CORS(app, resources={r"/*": {"origins": "*"}})

# RESTful routes
# Sign in
class SignIn(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400

        email = data.get('email')
        password = data.get('password')
       
        user = User.query.filter_by(email=email).first()
       
        if not user:
            return {"error": "User does not exist"}, 401
        if not bcrypt.check_password_hash(user.password, password):
            return {"error": "Incorrect password"}, 401
       
        access_token = create_access_token(identity={'id': user.id})
        refresh_token = create_refresh_token(identity={'id': user.id})
        return {"access_token": access_token, "refresh_token": refresh_token}, 200

api.add_resource(SignIn, '/signin')

# Sign up
class SignUp(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400
        
        # validate data
        errors = {}
        
        if not data.get('first_name'):
            errors['first_name'] = "First name should not be empty"
        
        if not data.get('last_name'):
            errors['last_name'] = "Last name should not be empty"
        
        email = data.get('email')
        if not email:
            errors['email'] = "Email should not be empty"
        elif '@' not in email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors['email'] = "Invalid email format"
        
        password = data.get('password')
        password_errors = []
        if not password:
            password_errors.append("Password should not be empty")
        else:
            if len(password) < 6:
                password_errors.append("Password should be at least 6 characters long")
            if not re.search(r"[A-Z]", password):
                password_errors.append("Password should contain at least one uppercase letter")
            if not re.search(r"[a-z]", password):
                password_errors.append("Password should contain at least one lowercase letter")
            if not re.search(r"[0-9]", password):
                password_errors.append("Password should contain at least one digit")
            if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                password_errors.append("Password should contain at least one special character")
        
        if password_errors:
            errors['password'] = password_errors
        
        if errors:
            return {"error": errors}, 400
        
        try:
            user = User(
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                password=data['password']
            )
            
            db.session.add(user)
            db.session.flush()
        except IntegrityError as error:
            db.session.rollback()
            return {"error": "Email already exists"}, 400
        except Exception as error:
            db.session.rollback()
            return {"error": str(error)}, 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user.password = hashed_password
       
        db.session.commit()
       
        access_token = create_access_token(identity={'id': user.id})
        refresh_token = create_refresh_token(identity={'id': user.id})
        return make_response({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict()
        }, 201)

api.add_resource(SignUp, '/signup')

# Refresh Token
class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    def post(self):
        try:
            current_user = get_jwt_identity()
            access_token = create_access_token(identity=current_user)
            return {'access_token': access_token}, 200
        except Exception as e:
            return jsonify(error=str(e)), 500

api.add_resource(TokenRefresh, '/refresh-token')

# Users (get post)
class Users(Resource):
    @jwt_required()
    def get(self):        
        users = [user.to_dict() for user in User.query.all()]
        return make_response(users,200)
     
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400
   
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            password=hashed_password
            )
       
        db.session.add(user)
        db.session.commit()
        return make_response(user.to_dict(), 201)
   
api.add_resource(Users, '/users')

# User By ID (get patch delete)
class UserByID(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        
        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return {"error": "User not found"}, 404
        response_dict = user.to_dict()
        return make_response(response_dict, 200)
   
    @jwt_required()
    def patch(self):
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        
        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return {"error": "User not found"}, 404
    
        # Check if the old password is provided and matches
        if 'old_password' in request.form and 'new_password' in request.form:
            old_password = request.form['old_password']
            new_password = request.form['new_password']
            if not bcrypt.check_password_hash(user.password, old_password):
                return {"error": "Old password does not match"}, 401
    
            # Update to the new password
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        else:
            if 'first_name' in request.form:
                user.first_name = request.form['first_name']
            if 'last_name' in request.form:
                user.last_name = request.form['last_name']
            if 'email' in request.form:
                user.email = request.form['email']
            if 'bio' in request.form:
                user.bio = request.form['bio']
            if 'image' in request.files:
                image = request.files['image']
                user.upload_image(image)
    
        try:
            db.session.commit()
            return make_response(user.to_dict(), 200)
        except AssertionError:
            return {"errors": ["validation errors"]}, 400

    @jwt_required()
    def delete(self):             
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        
        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return {"error": "User not found"}, 404
    
        db.session.delete(user)
        db.session.commit()
        return make_response({'message': 'User deleted successfully'})
   
api.add_resource(UserByID, '/user')

# Activities (get post)
class Activities(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        # Filter activities based on user_id
        activities = [activity.to_dict() for activity in Activity.query.filter_by(user_id=user_id).all()]
        return make_response(activities, 200)
   
    @jwt_required()
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400

        # Data validation
        required_fields = ['title', 'description', 'location', 'category']
        if any(field not in data or not data[field] for field in required_fields):
            return {"error": "Missing required fields"}, 400

        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        try:
            activity = Activity(
                title=data['title'],
                description=data['description'],
                location=data['location'],
                category=data['category'],
                user_id=user_id
            )

            db.session.add(activity)
            db.session.commit()
        except Exception as e:
            return {"error": "Internal server error"}, 500

        return make_response(activity.to_dict(), 201)

api.add_resource(Activities, '/activities')

# Activity By ID (get patch delete)
class ActivityByID(Resource):
    @jwt_required()
    def get(self, id):
        activity = Activity.query.filter_by(id=id).first()
        if activity is None:
            return {"error": "Activity not found"}, 404
        response_dict = activity.to_dict()
        return make_response(response_dict, 200)
   
    @jwt_required()
    def patch(self, id):
        activity = Activity.query.filter_by(id=id).first()
        if activity is None:
            return {"error": "Activity not found"}, 404

        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400

        if 'title' in data:
            activity.title = data['title']
        if 'description' in data:
            activity.body = data['description']
        if 'reviews' in data:
            activity.body = data['reviews']
        if 'rating' in data:
            activity.body = data['rating']
        if 'location' in data:
            activity.body = data['location']
        if 'category' in data:
            activity.category = data['category']
        if 'created_at' in data:
            activity.created_at = data['created_at']

        try:
            db.session.commit()
            return make_response(activity.to_dict(), 200)
        except AssertionError:
            return {"errors": ["validation errors"]}, 400

    @jwt_required()
    def delete(self, id):             
        activity = Activity.query.filter_by(id=id).first()
        if activity is None:
            return {"error": "Activity not found"}, 404
        
       
        activity = Activity.query.get_or_404(id)
        db.session.delete(activity)
        db.session.commit()
        return make_response({'message': 'Activity deleted successfully'})
         
api.add_resource(ActivityByID, '/activity/<int:id>')

# Activities By Date
class ActivitiesByDate(Resource):
    @jwt_required()
    def get(self, time_frame):
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)

        now = datetime.now(timezone.utc)
        if time_frame == 'all':
            activities = Activity.query.filter_by(user_id=user_id).all()
        else:
            start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
            if time_frame == 'daily':
                start_date = start_of_today
            elif time_frame == 'weekly':
                start_date = start_of_today - timedelta(days=now.weekday())
            elif time_frame == 'monthly':
                start_date = start_of_today.replace(day=1)
            else:
                return make_response({"error": "Invalid time frame"}, 400)

            activities = Activity.query.filter(Activity.user_id == user_id, Activity.created_at >= start_date, Activity.created_at <= now).all()

        activities_dict = [activity.to_dict() for activity in activities]

        return make_response({"activities": activities_dict}, 200)

api.add_resource(ActivitiesByDate, '/activities/<string:time_frame>')

if __name__ == '__main__':
    app.run(debug=True, port=5500)