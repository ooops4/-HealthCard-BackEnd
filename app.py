from flask import Flask, jsonify, request, json
from flask_pymongo  import PyMongo
from bson.json_util import dumps
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash,check_password_hash
from flask_cors import CORS, cross_origin
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

app=Flask(__name__)

app.config['MONGO_URI']="mongodb://localhost:27017/test123"
app.config['JWT_SECRET_KEY'] = "secretkey"

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)


#registration of users
@app.route('/api/register', methods=['POST'])
def register():
    users = mongo.db.users
    first_name = request.get_json()['first_name']
    last_name = request.get_json()['last_name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    created = datetime.utcnow()

    user_id = users.insert({
	'first_name' : first_name, 
	'last_name' : last_name, 
	'email' : email, 
	'password' : password, 
	'created' : created, 
	})
    new_user = users.find_one({'_id' : user_id})

    result = {'email' : new_user['email'] + ' registered'}

    return jsonify({'result' : result})
	

#login of user

@app.route('/api/login', methods=['POST'])
def login():
    users = mongo.db.users
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'first_name': response['first_name'],
				'last_name': response['last_name'],
				'email': response['email']}
				)
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid username and password"})            
    else:
        result = jsonify({"result":"No results found"})
    return result

#getting all the user
@app.route('/api/users/', methods=['GET'])
def get_all_users():
    user = mongo.db.user
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'first_name':field['first_name']})
    # *resp = dumps(users)
    return jsonify(result)


# #adding new user
# @app.route('/api/users', methods=['POST'])
# def add_user():
  
#     user = mongo.db.user
#     name = request.get_json()['name']
#     user_id = user.insert({'name': name})
#     new_user = user.find_one({'_id': user_id})

#     result = {'name': new_user['name']}
#     return jsonify({'result': result})




#updating by <id> details
@app.route('/api/user/<id>', methods=['PUT'])
def userss(id):
    user=mongo.db.user
    name=request.get_json()['name']
    user.find_one_and_update({'_id': ObjectId(id)}, {'$set':{'name':name}},upsert=False)
    new_user = user.find_one({'_id': ObjectId(id)})
    result = {'name': new_user['name']}
    return jsonify({'result': result})

@app.route('/api/user/<id>',methods=['DELETE'])
def delete_user(id):
    user=mongo.db.user
    response = user.delete_one({'_id': ObjectId(id)})
    if response.deleted_count == 1:
        result= {'message':'record deleted'}
    else:
        result= {'message':'No record deleted'}

    return jsonify({'result': result})


#chdsadsadasdsad

@app.route('/api/user/<id>',methods=['GET'])
def view_details(id):
    user = mongo.db.user
    field = user.find_one({'_id':ObjectId(id)})
    if field:
        output={'name':field['name'],'city':field['city']}
    else:
        output = "No such name"
    return jsonify({'result': output})
    
 











    # user=mongo.db.user
    # result = []
    # for field in user.find_one({'_id':ObjectId(id)}):
    #     result.append({ 'name':field['name'], 'city':field['city']})
    
    # return jsonify(result)
 


app.errorhandler(404)
def not_found(error=None):
    message = {
        'status':404,
        'message':'Not found blah blah' + request.url
    }
    resp = jsonify(message)

    resp.status_code = 404

    return resp

if __name__ == "__main__":
    app.run(debug=True)
