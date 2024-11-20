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

from models import db, User, Activity, UserActivity

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
class LogIn(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400

        email = data.get('email').lower()
        password = data.get('password')
       
        user = User.query.filter_by(email=email).first()
       
        if not user:
            return {"error": "User does not exist"}, 401
        if not bcrypt.check_password_hash(user.password, password):
            return {"error": "Incorrect password"}, 401
       
        access_token = create_access_token(identity={'id': user.id})
        refresh_token = create_refresh_token(identity={'id': user.id})
        return {"access_token": access_token, "refresh_token": refresh_token}, 200

api.add_resource(LogIn, '/login')

# Sign up
class Register(Resource):
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "Missing data in request"}, 400
        
        try:
            user = User(
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'].lower(),
                password=data['password']
            )
            
            db.session.add(user)
            db.session.flush()
        except IntegrityError as error:
            db.session.rollback()
            return {"error": "Email already exists"}, 400
        except AssertionError as error:
            db.session.rollback()
            return {"error": error.args[0]}, 400
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

api.add_resource(Register, '/register')

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

        data = request.form.to_dict()
        if 'new_password' in data:
            if 'old_password' not in data:
                return {"error": "Old password is required to set a new password"}, 400
            
            old_password = data['old_password']
            if not bcrypt.check_password_hash(user.password, old_password):
                return {"error": "Old password does not match"}, 401

            if bcrypt.check_password_hash(user.password, data['new_password']):
                return {"error": "New password cannot be the same as the old password"}, 400

            try:
                user.password = data['new_password']
                hashed_password = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
                user.password = hashed_password
            except AssertionError as error:
                return {"error": error.args[0]}, 400

        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'email' in data:
            user.email = data['email'].lower()
        if 'bio' in data:
            user.bio = data['bio']
        if 'image' in request.files:
            image = request.files['image']
            user.upload_image(image)

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

        activities = [activity.to_dict() for activity in Activity.query.filter_by(user_id=user_id).all()]
        return make_response(activities, 200)
   
    @jwt_required()
    def post(self):
        data = request.form.to_dict()
        if not data and 'image' not in request.files:
            return {"error": "Missing data in request"}, 400

        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        try:
            start_date = datetime.fromisoformat(data['start_date']).replace(tzinfo=timezone.utc)
            end_date = datetime.fromisoformat(data['end_date']).replace(tzinfo=timezone.utc)
            start_of_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

            # Validate start date
            if start_date < start_of_today:
                return {"error": "Start date should be today or in the future"}, 400

            # Validate end date
            if end_date < start_of_today:
                return {"error": "End date should be today or in the future"}, 400
            if end_date < start_date:
                return {"error": "End date should be equal to or after the start date"}, 400

            activity = Activity(
                title=data['title'],
                description=data['description'],
                location=data['location'],
                category=data['category'],
                start_date=start_date,
                end_date=end_date,
                user_id=user_id
            )

            activity.upload_image(request.files['image'])

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

        if 'start_date' in data:
            start_date = datetime.fromisoformat(data['start_date']).replace(tzinfo=timezone.utc)
            start_of_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            if start_date < start_of_today:
                return {"error": "Start date should be today or in the future"}, 400
            activity.start_date = start_date

        if 'end_date' in data:
            end_date = datetime.fromisoformat(data['end_date']).replace(tzinfo=timezone.utc)
            start_of_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            if end_date < start_of_today:
                return {"error": "End date should be today or in the future"}, 400
            if end_date < activity.start_date:
                return {"error": "End date should be equal to or after the start date"}, 400
            activity.end_date = end_date

        if 'title' in data:
            activity.title = data['title']
        if 'description' in data:
            activity.description = data['description']
        if 'location' in data:
            activity.location = data['location']
        if 'category' in data:
            activity.category = data['category']
        if 'image' in request.files:
            activity.upload_image(request.files['image'])

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

# Bookmark Activity
class BookmarkActivity(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        status = request.args.get('status', '').lower()
        if status == 'all':
            user_activities = UserActivity.query.filter_by(user_id=user_id).all()
        else:
            user_activities = UserActivity.query.filter_by(user_id=user_id, status=status).all()
        
        activities = [user_activity.activity.to_dict() for user_activity in user_activities]
        return make_response(activities, 200)
    
    @jwt_required()
    def post(self, activity_id):
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        existing_bookmark = UserActivity.query.filter_by(user_id=user_id, activity_id=activity_id).first()
        if existing_bookmark:
            return {"error": "Activity has already been bookmarked"}, 400

        activity = Activity.query.filter_by(id=activity_id).first()
        if not activity:
            return {"error": "Activity not found"}, 404

        current_time = datetime.now(timezone.utc)

        if activity.end_date.tzinfo is None:
            activity.end_date = activity.end_date.replace(tzinfo=timezone.utc)

        if current_time > activity.end_date:
            return {"error": "Activity has already ended"}, 400

        status = 'pending'
        priority = 'normal'

        user_activity = UserActivity(
            user_id=user_id,
            activity_id=activity_id,
            status=status,
            priority=priority            
        )

        db.session.add(user_activity)
        db.session.commit()
        return make_response(user_activity.to_dict(), 201)

    @jwt_required()
    def patch(self, activity_id):
        user_id = get_jwt_identity().get('id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
    
        data = request.get_json()
        if not data:
            return {"error": "No data provided"}, 400
    
        user_activity = UserActivity.query.filter_by(user_id=user_id, activity_id=activity_id).first()
        if not user_activity:
            return {"error": "Bookmark not found"}, 404
    
        if 'status' in data:
            status = data.get('status', '').lower()
            user_activity.status = status
    
        if 'priority' in data:
            priority = data.get('priority', '').lower()
            user_activity.priority = priority
    
        db.session.commit()
        return make_response(user_activity.to_dict(), 200)

api.add_resource(BookmarkActivity, '/bookmark-activity', '/bookmark-activity/<int:activity_id>')

if __name__ == '__main__':
    app.run(debug=False)