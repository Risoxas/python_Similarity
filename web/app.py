from turtle import pos
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import spacy

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB
users = db["Users"]


def user_exists(username):
    """Checks if user exists

    Args:
        username String: Username to check

    Returns:
        boolean: True if user exists, False if user doesn't exist
    """
    if users.count_documents({"username": username}) == 0:
        return False
    return True


def verify_password(username, password):
    """Checks if password is correct

    Args:
        username string: username to check
        password string: password to match

    Returns:
        boolean: True if password matches, False if it doesn't
    """
    hashed_pw = users.find({"username": username})[0]["password"]

    if bcrypt.hashpw(password.encode('utf-8'), hashed_pw) == hashed_pw:
        return True
    return False


def count_tokens(username):
    """Checks number of tokens in user

    Args:
        username (string): username to check

    Returns:
        number: number of tokens
    """
    return users.find({"username": username})[0]["tokens"]


class Register(Resource):
    """Register UseCase

    Args:
        Resource Resource: flask_restful Resource
    """

    def post(self):
        """Post endpoint

        Returns:
            json: Response to request
        """
        posted_data = request.get_json()
        username = posted_data["username"]
        password = posted_data["password"]
        if user_exists(username):
            ret_json = {
                "status": 301,
                "msg": "Invalid username"
            }
            return jsonify(ret_json)
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users.insert_one({
            "username": username,
            "password": hashed_pw,
            "tokens": 6
        })

        ret_json = {
            "status": 200,
            "msg": "You've successfully signed up to the API"
        }
        return jsonify(ret_json)


class Detect(Resource):
    """Detect UseCase

    Args:
        Resource Resource: restful_flask resource
    """

    def post(self):
        """Post endpoint

        Returns:
            json: Api response
        """
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]
        text1 = posted_data["text1"]
        text2 = posted_data["text2"]

        if not user_exists(username):
            ret_json = {
                "status": 301,
                "msg": "Invalida Username"
            }
            return jsonify(ret_json)
        correct_pw = verify_password(username, password)

        if not correct_pw:
            ret_json = {
                "status": 302,
                "msg": "Invalid password"
            }
            return jsonify(ret_json)
        num_tokens = count_tokens(username)

        if num_tokens <= 0:
            ret_json = {
                "status": 303,
                "msg": "You're out of tokens, refill"
            }
            return jsonify(ret_json)

        natural_language = spacy.load('en_core_web_sm')

        text1 = natural_language(text1)
        text2 = natural_language(text2)

        ratio = text1.similarity(text2)

        ret_json = {
            "status": 200,
            "similarity": ratio,
            "msg": "Similarity score calculated successfully"
        }

        users.update_one({
            "username": username
        }, {
            "$set": {
                "tokens": num_tokens-1
            }
        })

        return jsonify(ret_json)


class Refill(Resource):
    """Refill UseCase

    Args:
        Resource (Resource): restful_flask Resource
    """

    def post(self):
        """Refills tokens for desired user

        Returns:
            json: response
        """
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]
        refill_amount = posted_data["refill"]

        if not user_exists(username):
            ret_json = {
                "status": 301,
                "msg": "Invalid Username"
            }
            return jsonify(ret_json)
        correct_pw = verify_password(username, password)
        if not correct_pw:
            ret_json = {
                "status": 304,
                "msg": "Invalid Password"
            }
            return jsonify(ret_json)
        current_tokens = count_tokens(username)
        users.update_one({
            "username": username
        }, {
            "$set": {
                "tokens": refill_amount+current_tokens
            }
        })
        ret_json = {
            "status": 200,
            "msg": "Tokens refilled successfully"
        }
        return jsonify(ret_json)


api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')

if __name__ == '__main__':
    app.run(host='0.0.0.0')
