from flask import Flask
from flask import request
from flask_restful import reqparse, abort, Api, Resource
import bcrypt
import uuid
import jwt
from flask import request, current_app, after_this_request
import datetime

app = Flask(__name__)
api = Api(app)
users = {
	
}

SECRET_KEY = ""


parser = reqparse.RequestParser()
parser.add_argument('username', type=str, required=True, help="Username cannot be blank")
parser.add_argument('password', type=str, required=True, help="password cannot be blank")

def generate_nonce():
    return uuid.uuid4().hex + uuid.uuid1().hex

SECRET_KEY = generate_nonce()


def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=60),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            SECRET_KEY,
            algorithm='HS256'
        )
    except Exception as e:
        return e

def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, SECRET_KEY)
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

class SignUp(Resource):
	def get(self):
		return users

	def post(self):
		args = parser.parse_args()

		if args['username'] in users:
			return {'message': "user already exists"}, 409

		if not args['username'].strip() or not args['password'].strip():
			return {'message': "invalid arguments"}, 422

		salt = bcrypt.gensalt(14)
		hashed = bcrypt.hashpw(args['password'].encode('utf-8'), salt)

		users[args['username']] = hashed
		
		return {'message': 'Sign-Up complete'}, 201

class Login(Resource):
	def post(self):
		args = parser.parse_args()

		if args['username'] not in users:
			return "wrong username/password", 401
		elif not bcrypt.checkpw(args['password'].encode('utf-8'), users[args['username']]):
			return "wrong username/password", 401
		else:
			token = encode_auth_token(args['username'])
			print(token.decode('utf-8'))
			return {'message': 'success'}, 200, {'Set-Cookie': "token={};Path=/".format(token.decode('utf-8'))}

class Messages(Resource):
	def get(self):
		if 'token' in request.cookies:
			token = request.cookies.get('token')
			token = decode_auth_token(token.encode('utf-8'))
			return {'message': token}, 200
		else:
			return {'message': "No token"}, 401

api.add_resource(SignUp, '/api/auth/signup')
api.add_resource(Login, '/api/auth/login')
api.add_resource(Messages, '/api/messages')

if __name__ == '__main__':
	app.run(debug=True)

