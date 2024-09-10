from flask import Flask, request, make_response, jsonify
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, create_refresh_token
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
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

# Validate Old Password
class ValidateOldPassword(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return {"error": "User not found"}, 404

        data = request.get_json()
        if not data or 'old_password' not in data:
            return {"error": "Old password is required"}, 400

        old_password = data['old_password']
        if not bcrypt.check_password_hash(user.password, old_password):
            return {"error": "Old password does not match"}, 401

        return {"message": "Old password is valid"}, 200

api.add_resource(ValidateOldPassword, '/validate-old-password')

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
    
        errors = {}
    
        if 'new_password' in request.form:
            new_password = request.form['new_password']
            # Validate new password
            try:
                assert len(new_password) >= 6, "Password should be at least 6 characters long"
                assert re.search(r"[A-Z]", new_password), "Password should contain at least one uppercase letter"
                assert re.search(r"[a-z]", new_password), "Password should contain at least one lowercase letter"
                assert re.search(r"[0-9]", new_password), "Password should contain at least one digit"
                assert re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password), "Password should contain at least one special character"
                user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            except AssertionError as error:
                errors['password'] = str(error)
        if 'first_name' in request.form:
            try:
                assert len(request.form['first_name']) > 0, "First name should not be empty"
                user.first_name = request.form['first_name']
            except AssertionError as error:
                errors['first_name'] = str(error)
        if 'last_name' in request.form:
            try:
                assert len(request.form['last_name']) > 0, "Last name should not be empty"
                user.last_name = request.form['last_name']
            except AssertionError as error:
                errors['last_name'] = str(error)
        if 'email' in request.form:
            try:
                email = request.form['email']
                assert '@' in email, 'Invalid email format'
                assert re.match(r"[^@]+@[^@]+\.[^@]+", email), 'Invalid email format'
                user.email = email
            except AssertionError as error:
                errors['email'] = str(error)
        if 'bio' in request.form:
            try:
                bio = request.form['bio']
                word_count = len(bio.split())
                assert word_count <= 50, "Bio should not exceed 50 words"
                user.bio = bio
            except AssertionError as error:
                errors['bio'] = str(error)
        if 'image' in request.files:
            image = request.files['image']
            user.upload_image(image)
    
        if errors:
            return {"errors": errors}, 400
    
        try:
            db.session.commit()
            return make_response(user.to_dict(), 200)
        except Exception as error:
            db.session.rollback()
            return {"error": str(error)}, 500

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

# All Activities (get)
class AllActivities(Resource):
    @jwt_required()
    def get(self):
        activities = [activity.to_dict() for activity in Activity.query.all()]
        return make_response(activities, 200)

api.add_resource(AllActivities, '/activities/all')
    
# User Activities (get post)
class UserActivities(Resource):
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
        data = request.form.to_dict()
        if not data and 'image' not in request.files:
            return {"error": "Missing data in request"}, 400

        errors = {}

        if 'title' in data:
            try:
                word_count = len(data['title'].split())
                assert word_count <= 10, "Title should not exceed 10 words"
            except AssertionError as error:
                errors['title'] = str(error)
        else:
            errors['title'] = "Title is required"

        if 'description' in data:
            try:
                word_count = len(data['description'].split())
                assert word_count <= 50, "Description should not exceed 50 words"
            except AssertionError as error:
                errors['description'] = str(error)
        else:
            errors['description'] = "Description is required"

        if 'location' in data:
            try:
                assert len(data['location']) > 0, "Location should be provided"
            except AssertionError as error:
                errors['location'] = str(error)
        else:
            errors['location'] = "Location is required"

        if 'category' in data:
            try:
                allowed_categories = ['Outdoors', 'Indoors', 'General']
                assert data['category'] in allowed_categories, f"Category should be one of {allowed_categories}"
            except AssertionError as error:
                errors['category'] = str(error)
        else:
            errors['category'] = "Category is required"

        if 'start_date' in data:
            try:
                start_date = datetime.fromisoformat(data['start_date']).replace(tzinfo=timezone.utc)
                start_of_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                assert start_date.date() >= start_of_today.date(), "Start date should be equal to today or in the future"
                activity.start_date = start_date
            except (ValueError, AssertionError) as error:
                errors['start_date'] = str(error)
        else:
            errors['start_date'] = "Start date is required"

        if 'end_date' in data:
            try:
                end_date = datetime.fromisoformat(data['end_date']).replace(tzinfo=timezone.utc)
                if activity.start_date.tzinfo is None:
                    activity.start_date = activity.start_date.replace(tzinfo=timezone.utc)
                assert end_date >= activity.start_date, "End date should be equal to or after the start date"
                activity.end_date = end_date
            except (ValueError, AssertionError) as error:
                errors['end_date'] = str(error)
        else:
            errors['end_date'] = "End date is required"

        if 'image' in request.files:
            image = request.files['image']
        else:
            errors['image'] = "Image is required"

        if errors:
            return {"errors": errors}, 400

        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        try:
            activity = Activity(
                title=data['title'],
                description=data['description'],
                location=data['location'],
                category=data['category'],
                start_date=start_date,
                end_date=end_date,
                user_id=user_id
            )

            activity.upload_image(image)

            db.session.add(activity)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {"error": "Internal server error"}, 500

        return make_response(activity.to_dict(), 201)
    
api.add_resource(UserActivities, '/activities')

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

        data = request.form.to_dict()
        if not data and 'image' not in request.files:
            return {"error": "Missing data in request"}, 400

        errors = {}

        if 'title' in data:
            try:
                word_count = len(data['title'].split())
                assert word_count <= 10, "Title should not exceed 10 words"
                activity.title = data['title']
            except AssertionError as error:
                errors['title'] = str(error)
        else:
            errors['title'] = "Title is required"

        if 'description' in data:
            try:
                word_count = len(data['description'].split())
                assert word_count <= 50, "Description should not exceed 50 words"
                activity.description = data['description']
            except AssertionError as error:
                errors['description'] = str(error)
        else:
            errors['description'] = "Description is required"

        if 'reviews' in data:
            try:
                word_count = len(data['reviews'].split())
                assert word_count <= 30, "Reviews should not exceed 30 words"
                activity.reviews = data['reviews']
            except AssertionError as error:
                errors['reviews'] = str(error)

        if 'rating' in data:
            try:
                rating = int(data['rating'])
                assert 0 <= rating <= 5, "Rating must be between 0 and 5"
                activity.rating = rating
            except (ValueError, AssertionError) as error:
                errors['rating'] = str(error)

        if 'location' in data:
            try:
                assert len(data['location']) > 0, "Location should be provided"
                activity.location = data['location']
            except AssertionError as error:
                errors['location'] = str(error)
        else:
            errors['location'] = "Location is required"

        if 'category' in data:
            try:
                allowed_categories = ['Outdoors', 'Indoors', 'General']
                assert data['category'] in allowed_categories, f"Category should be one of {allowed_categories}"
                activity.category = data['category']
            except AssertionError as error:
                errors['category'] = str(error)
        else:
            errors['category'] = "Category is required"

        if 'start_date' in data:
            try:
                start_date = datetime.fromisoformat(data['start_date']).replace(tzinfo=timezone.utc)
                start_of_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                assert start_date.date() >= start_of_today.date(), "Start date should be equal to today or in the future"
                activity.start_date = start_date
            except (ValueError, AssertionError) as error:
                errors['start_date'] = str(error)
        else:
            errors['start_date'] = "Start date is required"

        if 'end_date' in data:
            try:
                end_date = datetime.fromisoformat(data['end_date']).replace(tzinfo=timezone.utc)
                if activity.start_date.tzinfo is None:
                    activity.start_date = activity.start_date.replace(tzinfo=timezone.utc)
                assert end_date >= activity.start_date, "End date should be equal to or after the start date"
                activity.end_date = end_date
            except (ValueError, AssertionError) as error:
                errors['end_date'] = str(error)
        else:
            errors['end_date'] = "End date is required"

        if 'image' in request.files:
            image = request.files['image']
            activity.upload_image(image)
        else:
            errors['image'] = "Image is required"

        if errors:
            return {"errors": errors}, 400

        try:
            db.session.commit()
            return make_response(activity.to_dict(), 200)
        except Exception as error:
            db.session.rollback()
            return {"error": str(error)}, 500

    @jwt_required()
    def delete(self, id):
        activity = Activity.query.get_or_404(id)
        db.session.delete(activity)
        db.session.commit()
        return make_response({'message': 'Activity deleted successfully'}, 200)

api.add_resource(ActivityByID, '/activity/<int:id>')

class ActivitiesByDate(Resource):
    @jwt_required()
    def get(self):
        date_str = request.args.get('date')

        if date_str:
            date = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
        else:
            date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        query = Activity.query.filter(
            func.date(Activity.start_date) <= date.date(),
            func.date(Activity.end_date) >= date.date()
        )

        activities = [activity.to_dict() for activity in query.all()]
        return make_response({"activities": activities}, 200)

api.add_resource(ActivitiesByDate, '/activities/date')

if __name__ == '__main__':
    app.run(debug=True, port=5500)