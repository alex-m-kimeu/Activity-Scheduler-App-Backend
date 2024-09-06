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
            first_name='John',
            last_name='Doe',
            email='john.doe@example.com',
            password=bcrypt.generate_password_hash("Password123!").decode('utf-8'),
            bio='A sample bio for John Doe.',
            image='http://example.com/image1.jpg'
        )

        user2 = User(
            first_name='Jane',
            last_name='Smith',
            email='jane.smith@example.com',
            password=bcrypt.generate_password_hash("Password123!").decode('utf-8'),
            bio='A sample bio for Jane Smith.',
            image='http://example.com/image2.jpg'
        )

        # Create sample activities with different created_at dates
        activity1 = Activity(
            title='Hiking',
            description='A fun hiking activity.',
            reviews='Great experience!',
            rating=5,
            location='Mountain Trail',
            category='Outdoor',
            created_at=datetime.now(timezone.utc) - timedelta(days=10),
            user=user1
        )

        activity2 = Activity(
            title='Cooking Class',
            description='Learn to cook delicious meals.',
            reviews='Very informative!',
            rating=4,
            location='Cooking Studio',
            category='Indoor',
            created_at=datetime.now(timezone.utc) - timedelta(days=2),
            user=user1
        )

        activity3 = Activity(
            title='Yoga Session',
            description='A relaxing yoga session.',
            reviews='Very calming!',
            rating=5,
            location='Yoga Center',
            category='Wellness',
            created_at=datetime.now(timezone.utc) - timedelta(days=1),
            user=user1
        )

        activity4 = Activity(
            title='Painting Workshop',
            description='Learn to paint beautiful landscapes.',
            reviews='Very creative!',
            rating=4,
            location='Art Studio',
            category='Art',
            created_at=datetime.now(timezone.utc),
            user=user1
        )

        # Add users and activities to the session
        db.session.add(user1)
        db.session.add(user2)
        db.session.add(activity1)
        db.session.add(activity2)
        db.session.add(activity3)
        db.session.add(activity4)

        # Commit the session to save the data
        db.session.commit()
        print("Database seeded successfully!")
