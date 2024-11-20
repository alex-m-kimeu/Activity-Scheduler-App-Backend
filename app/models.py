from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates, relationship
import re
from datetime import datetime, timezone
import cloudinary.uploader

db = SQLAlchemy()

# User Model
class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    # columns
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(), nullable=False)
    last_name = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    bio = db.Column(db.Text(), nullable=True)
    image = db.Column(db.String(), nullable=True)

    # relationships
    activities = relationship('Activity', back_populates='user', cascade='all, delete-orphan')
    user_activities = relationship('UserActivity', back_populates='user', cascade='all, delete-orphan')

    # serialization rules
    serialize_rules = ('-activities', '-user_activities')

    # validations
    @validates('first_name')
    def validate_first_name(self, key, first_name):
        assert len(first_name) > 0, "First name should not be empty"
        return first_name
    
    @validates('last_name')
    def validate_last_name(self, key, last_name):
        assert len(last_name) > 0, "Last name should not be empty"
        return last_name

    @validates('email')
    def validate_email(self, key, email):
        assert '@' in email, 'Invalid email format'
        assert re.match(r"[^@]+@[^@]+\.[^@]+", email), 'Invalid email format'
        return email
    
    @validates('bio')
    def validate_bio(self, key, bio):
        word_count = len(bio.split())
        assert word_count <= 50, "Bio should not exceed 50 words"
        return bio
    
    @validates('password')
    def validate_password(self, key, password):
        errors = []
        if len(password) < 6:
            errors.append("Password should be at least 6 characters long")
        if not re.search(r"[A-Z]", password):
            errors.append("Password should contain at least one uppercase letter")
        if not re.search(r"[a-z]", password):
            errors.append("Password should contain at least one lowercase letter")
        if not re.search(r"[0-9]", password):
            errors.append("Password should contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password should contain at least one special character")
        
        if errors:
            raise AssertionError(errors)
        
        return password
    
    # Uploading profile picture
    def upload_image(self, image):
        upload_result = cloudinary.uploader.upload(image)
        self.image = upload_result['url']

# Activity Model
class Activity(db.Model, SerializerMixin):
    __tablename__ = 'activities'

    # columns
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(), nullable=False)
    description = db.Column(db.Text(), nullable=False)
    location = db.Column(db.String(), nullable=False)
    category = db.Column(db.String(), nullable=False, default='General')
    image = db.Column(db.String(), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)

    # foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # relationships
    user = relationship('User', back_populates='activities')
    user_activities = relationship('UserActivity', back_populates='activity', cascade='all, delete-orphan')

    # serialization rules
    serialize_rules = ('-user', '-user_activities.user')

    # validations
    @validates('title')
    def validate_title(self, key, title):
        word_count = len(title.split())
        assert word_count <= 4, "Title should not exceed 4 words"
        return title

    @validates('description')
    def validate_body(self, key, description):
        word_count = len(description.split())
        assert word_count <= 50, "Description should not exceed 50 words"
        return description
    
    @validates('category')
    def validate_category(self, key, category):
        allowed_categories = ['Outdoors', 'Indoors', 'General']
        assert category in allowed_categories, f"Category should be one of {allowed_categories}"
        return category
    
    @validates('location')
    def validate_title(self, key, location):
        assert len(location) > 0, "Location should be provided"
        return location
    
    # Uploading picture
    def upload_image(self, image):
        upload_result = cloudinary.uploader.upload(image)
        self.image = upload_result['url']

class UserActivity(db.Model, SerializerMixin):
    __tablename__ = 'user_activities'

    # columns
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    activity_id = db.Column(db.Integer, db.ForeignKey('activities.id'), nullable=False)
    status = db.Column(db.String(), nullable=False, default='Pending')
    priority = db.Column(db.String(), nullable=False, default='normal')

    # serialization rules
    serialize_rules = ('-user', '-activity')
    
    # relationships
    user = relationship('User', back_populates='user_activities')
    activity = relationship('Activity', back_populates='user_activities')

    # validations
    @validates('status')
    def validate_status(self, key, status):
        allowed_statuses = ['pending', 'completed', 'cancelled', 'all']
        assert status in allowed_statuses, f"Status should be one of {allowed_statuses}"
        return status
    
    @validates('priority')
    def validate_priority(self, key, priority):
        allowed_priorities = ['low', 'normal', 'high']
        assert priority in allowed_priorities, f"Priority should be one of {allowed_priorities}"
        return priority