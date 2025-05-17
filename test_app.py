import unittest
from flask import url_for, session
from werkzeug.security import generate_password_hash
import jwt
import datetime
from unittest.mock import patch, MagicMock
from app import app, db, User, Course, Message, create_token, verify_token, get_ai_response

class TestFlaskApp(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()
        
        with app.app_context():
            db.create_all()
            self.add_test_data()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def add_test_data(self):
        # Add test user
        hashed_pass = generate_password_hash('testpass')
        user = User(username='testuser', email='test@example.com', password=hashed_pass)
        db.session.add(user)
        
        # Add test admin
        admin_pass = generate_password_hash('adminpass')
        admin = User(username='admin', email='admin@example.com', password=admin_pass, is_admin=True)
        db.session.add(admin)
        
        # Add test course
        course = Course(title='Python Course', description='Learn Python', 
                       image_url='python.jpg', course_type='programming', 
                       course_link='python-course')
        db.session.add(course)
        
        # Add test message
        message = Message(user_id=1, content='Test message')
        db.session.add(message)
        
        db.session.commit()

    def login(self, username, password):
        return self.app.post('/user/login', data={
            'username': username,
            'password': password
        }, follow_redirects=True)

    def logout(self):
        return self.app.get('/user/logout', follow_redirects=True)

    # Token Function Tests
    def test_token_creation_and_verification(self):
        # Test create_token
        token, exp = create_token(1)
        self.assertIsInstance(token, str)
        self.assertIsInstance(exp, datetime.datetime)
        
        # Test verify_token with valid token
        payload = verify_token(token)
        self.assertEqual(payload['user_id'], 1)
        
        # Test verify_token with expired token
        old_payload = {'user_id': 1, 'exp': datetime.datetime.utcnow() - datetime.timedelta(hours=1)}
        old_token = jwt.encode(old_payload, app.secret_key, algorithm='HS256')
        result = verify_token(old_token)
        self.assertEqual(result, 'التوكن منتهي الصلاحية')
        
        # Test verify_token with invalid token
        result = verify_token('invalidtoken')
        self.assertEqual(result, 'توكن غير صالح')

    # Authentication Tests
    def test_user_registration(self):
        # Successful registration
        response = self.app.post('/user/register', data={
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'newpass',
            'confirm_password': 'newpass'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'login', response.data)
        
        # Check if user was actually created
        with app.app_context():
            user = User.query.filter_by(username='newuser').first()
            self.assertIsNotNone(user)

    def test_user_login_logout(self):
        # Successful login
        response = self.login('testuser', 'testpass')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'testuser', response.data)
        
        # Check session token was set
        self.assertIsNotNone(session.get('token'))
        
        # Logout
        response = self.logout()
        self.assertEqual(response.status_code, 200)
        self.assertIn('زائر', response.data)
        self.assertIsNone(session.get('token'))

    # Course Tests
    def test_course_operations(self):
        self.login('admin', 'adminpass')
        
        # Add new course
        response = self.app.post('/admin/add_course', data={
            'title': 'New Course',
            'description': 'New Description',
            'image_url': 'new.jpg',
            'course_type': 'design',
            'course_link': 'new-course'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'New Course', response.data)
        
        # View course detail
        response = self.app.get('/new-course')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'New Description', response.data)
        
        # Delete course
        course = Course.query.filter_by(title='New Course').first()
        response = self.app.post(f'/admin/admin_courses/{course.id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'New Course', response.data)

    # Message Tests
    def test_message_operations(self):
        self.login('testuser', 'testpass')
        
        # Send new message
        response = self.app.post('/user/contantgroup', data={
            'message': 'Hello World'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Hello World', response.data)
        
        # Delete message
        message = Message.query.filter_by(content='Hello World').first()
        response = self.app.post(f'/delete_message/{message.id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'Hello World', response.data)

    # Admin Tests
    def test_admin_functions(self):
        self.login('admin', 'adminpass')
        
        # User management
        response = self.app.get('/admin/users')
        self.assertEqual(response.status_code, 200)
        
        # Set admin privilege
        user = User.query.filter_by(username='testuser').first()
        response = self.app.post(f'/admin/users/{user.id}/set_admin', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        updated_user = User.query.get(user.id)
        self.assertTrue(updated_user.is_admin)
        
        # Delete user
        response = self.app.post(f'/admin/users/{user.id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(User.query.get(user.id))

    # API Tests
    def test_like_course_api(self):
        self.login('testuser', 'testpass')
        course = Course.query.first()
        
        response = self.app.post(f'/like/{course.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['success'], True)
        
        # Verify like count increased
        updated_course = Course.query.get(course.id)
        self.assertEqual(updated_course.likes, 1)

    @patch('app.httpx.AsyncClient')
    def test_ai_response_function(self, mock_client):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": "Mocked AI Response"
                    }]
                }
            }]
        }
        mock_client.return_value.__aenter__.return_value.post.return_value = mock_response
        
        # Test the function
        import asyncio
        response = asyncio.run(get_ai_response("test input"))
        self.assertEqual(response, "Mocked AI Response")

    # Route Tests
    def test_protected_routes(self):
        # Try to access profile without login
        response = self.app.get('/user/profile', follow_redirects=True)
        self.assertIn(b'login', response.data)
        
        # Try to access admin page as regular user
        self.login('testuser', 'testpass')
        response = self.app.get('/admin/index')
        self.assertEqual(response.status_code, 403)

if __name__ == '__main__':
    unittest.main()