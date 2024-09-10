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
    activities = relationship('Activity', back_populates='user' ,cascade='all, delete-orphan')

    # serialization rules
    serialize_rules = ('-activities',)

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
        assert len(password) >= 6, "Password should be at least 6 characters long"
        assert re.search(r"[A-Z]", password), "Password should contain at least one uppercase letter"
        assert re.search(r"[a-z]", password), "Password should contain at least one lowercase letter"
        assert re.search(r"[0-9]", password), "Password should contain at least one digit"
        assert re.search(r"[!@#$%^&*(),.?\":{}|<>]", password), "Password should contain at least one special character"
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
    reviews = db.Column(db.Text(), nullable=True)
    rating= db.Column(db.Integer(), nullable=True)
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

    # serialization rules
    serialize_rules = ('-user',)

    # validations
    @validates('title')
    def validate_title(self, key, title):
        word_count = len(title.split())
        assert word_count <= 10, "Title should not exceed 10 words"
        return title

    @validates('description')
    def validate_body(self, key, description):
        word_count = len(description.split())
        assert word_count <= 50, "description should not exceed 20 words"
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
    
    @validates('start_date')
    def validate_start_date(self, key, start_date):
        start_of_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        assert start_date >= start_of_today, "Start date should be today or in the future"
        return start_date
    
    @validates('end_date')
    def validate_end_date(self, key, end_date):
        start_of_today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        assert end_date >= start_of_today, "End date should be today or in the future"
        assert end_date >= self.start_date, "End date should be equal to or after the start date"
        return end_date
    
    # Uploading picture
    def upload_image(self, image):
        upload_result = cloudinary.uploader.upload(image)
        self.image = upload_result['url']
