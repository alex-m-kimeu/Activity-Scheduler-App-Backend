from models import db, User, Activity
from app import app
from datetime import datetime, timedelta, timezone
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

if __name__ == '__main__':
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()

        # Create sample users
        user1 = User(
            first_name='Reen',
            last_name='Muli',
            email='reen@gmail.com',
            password=bcrypt.generate_password_hash("Reen123!").decode('utf-8'),
            bio='Nature enthusiast with a passion for exploring the outdoors, wildlife, and sustainable living. Always chasing sunsets and new adventures in the wild.',
            image='http://res.cloudinary.com/dppzo29it/image/upload/v1725871003/bjpi5vxlqonrj5rsnja3.jpg'
        )

        # Create sample activities with different created_at dates
        activity1 = Activity(
            title='Camping Trip',
            description='A five day camping expedition along the mara. Kosa uchekwe!!!!!',
            image='http://res.cloudinary.com/dppzo29it/image/upload/v1725871204/krlssuniibyxxnlqiyih.jpg',
            location='The Mara',
            category='Outdoors',
            created_at=datetime.now(timezone.utc),
            start_date=datetime.now(timezone.utc) + timedelta(days=2),
            end_date=datetime.now(timezone.utc) + timedelta(days=7),
            user=user1
        )

        activity2 = Activity(
            title='Hiking',
            description='A one day hiking experience of the Ngong hills. Come one come all.',
            image='http://res.cloudinary.com/dppzo29it/image/upload/v1725872047/hfvguqgcxyra8zb8lby9.jpg',
            location='Ngong Hills',
            category='Outdoors',
            created_at=datetime.now(timezone.utc) - timedelta(days=7),
            start_date=datetime.now(timezone.utc) - timedelta(days=5),
            end_date=datetime.now(timezone.utc) - timedelta(days=2),
            user=user1
        )

        activity3 = Activity(
            title='Weekend Getaway to Diani',
            description='Come enjoy a weekend full of fun along the sandy beaches of Diani',
            location='Diani, Kenya',
            image='http://res.cloudinary.com/dppzo29it/image/upload/v1725872253/ccbbwmrmg44gzfdia4ne.jpg',
            category='Outdoors',
            created_at=datetime.now(timezone.utc),
            start_date=datetime.now(timezone.utc) + timedelta(days=7),
            end_date=datetime.now(timezone.utc) + timedelta(days=9),
            user=user1
        )

        # Add users and activities to the session
        db.session.add(user1)
        db.session.add(activity1)
        db.session.add(activity2)
        db.session.add(activity3)

        # Commit the session to save the data
        db.session.commit()
        print("Database seeded successfully!")