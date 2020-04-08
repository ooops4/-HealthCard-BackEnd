from flask import Flask
from flask_pymongo  import PyMongo
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import jsonify, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_cors import CORS, cross_origin

app=Flask(__name__)
app.secret_key = "secretkey"
app.config['MONGO_URI']="mongodb://localhost:27017/test123"
mongo = PyMongo(app)
CORS(app)



#getting all the user
@app.route('/api/users/', methods=['GET'])
def get_all_users():
    user = mongo.db.user
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'name':field['name']})
    # *resp = dumps(users)
    return jsonify(result)


#adding new user
@app.route('/api/users', methods=['POST'])
def add_user():
  
    user = mongo.db.user
    name = request.get_json()['name']
    user_id = user.insert({'name': name})
    new_user = user.find_one({'_id': user_id})

    result = {'name': new_user['name']}
    return jsonify({'result': result})




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
