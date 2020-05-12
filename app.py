import os
import upload
from flask import Flask, jsonify, request, json, redirect
from flask_pymongo  import PyMongo
from bson.json_util import dumps
import json
# import time
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash,check_password_hash
from flask_cors import CORS, cross_origin
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
import urllib.request
from werkzeug.utils import secure_filename



app=Flask(__name__)

app.config['MONGO_URI']="mongodb://localhost:27017/test123"
app.config['JWT_SECRET_KEY'] = "secretkey"
UPLOAD_FOLDER = 'assets/uploads/'

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)


###########################################################################################
########################            ADMIN API             #################################


########################       REGISTRATION OF USERS      #################################

@app.route('/api/register', methods=['POST'])
def registerAdmin():
    # check if the post request has the file part
    if 'profile_photo' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['profile_photo']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # dt = str(datetime.utcnow())
        # filenameplusdate = str(dt+filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/frontend/HealthCard/src/assets/uploads', filename))
        save_filename = (UPLOAD_FOLDER+filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        # def savefilenametodatabase():
        #     location = mongo.db.users

        resp.status_code = 201

    users = mongo.db.users
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    gender = request.form['gender']

    father_name = request.form['father_name']
    mother_name = request.form['mother_name']
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    age = request.form['age']
    # profile_photo = save_filename
    
    created = datetime.utcnow()
    print(created)

    user_id = users.insert({
	'first_name' : first_name, 
	'last_name' : last_name, 
	'email' : email, 
	'password' : password,
    'age' : age,
    'gender' : gender, 
	'created' : created, 
    'father_name':father_name,
    'mother_name':mother_name,
    'contact_number':contact_number,
    'emergency_contact_number':emergency_contact_number,
    'profile_photo':save_filename,
    'cases': {
    }




    # 'address': {
    #     city: city,
    #     state:'Gujarat',
        
    # },
	}),
    print('user_id isisisisisi', user_id)
    # new_user = users.find_one({'_id' : user_id})

    # result = {'email' : new_user['email'] + ' registered'}
    # print('result is ',result)
    return jsonify({'result' : 'user saved'})
	


########################       LOGIN OF ADMIN      #################################
@app.route('/api/login', methods=['POST'])
def loginAdmin():
    users = mongo.db.admin
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



###########################################################################################
########################            DOCTOR API            #################################


########################    REGISTRATION OF NEW DOCTOR    #################################
@app.route('/api/doctor/register', methods=['POST'])
def registerDoctor():
    print(request.get_json())
    users = mongo.db.doctors
    first_name = request.get_json()['first_name']
    last_name = request.get_json()['last_name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    gender = request.get_json()['gender']

    father_name = request.get_json()['father_name']
    mother_name = request.get_json()['mother_name']
    contact_number = request.get_json()['contact_number']
    emergency_contact_number= request.get_json()['emergency_contact_number']
    age = request.get_json()['age']
    qualification = request.get_json()['qualification']
    
    created = datetime.utcnow()

    user_id = users.insert({
	'first_name' : first_name, 
	'last_name' : last_name, 
	'email' : email, 
	'password' : password,
    'age' : age,
    'gender' : gender, 
	'created' : created, 
    'father_name':father_name,
    'mother_name':mother_name,
    'contact_number':contact_number,
    'emergency_contact_number':emergency_contact_number,
    'qualification':qualification



    # 'address': {
    #     city: city,
    #     state:'Gujarat',
        
    # },
	}),
    print('user_id isisisisisi', user_id)
    # new_user = users.find_one({'_id' : user_id})

    # result = {'email' : new_user['email'] + ' registered'}
    # print('result is ',result)
    return jsonify({'result' : 'user saved'})
	

##################### LOGIN OF DOCTOR

@app.route('/api/doctor/login', methods=['POST'])
def loginDoctor():
    users = mongo.db.doctors
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})
    print(response)
    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {'_id': str(response['_id'])}, expires_delta=None)
            result = jsonify({"token":access_token, "_id": str(response['_id']), 'name':response['first_name'] })
        else:
            result = jsonify({"error":"Invalid username and password"})            
    else:
        result = jsonify({"result":"No results found"})
    return result


##################### GETTING ALL THE DOCTORS ONLY NAMES ##########################
@app.route('/api/doctor/users', methods=['GET'])
def get_all_doctor_list():
    user = mongo.db.doctors
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'first_name':field['first_name'], 'last_name':field['last_name']})
    # *resp = dumps(users)
    return jsonify(result)





###########################################################################################
########################          HOSPITAL API            #################################


########################    REGISTRATION OF NEW HOSPITAL    #################################
@app.route('/api/hospital/register', methods=['POST'])
def registerHospital():
    print(request.get_json())
    users = mongo.db.doctors
    hospital_name = request.get_json()['hospital_name']
    first_name = request.get_json()['first_name']
    last_name = request.get_json()['last_name']
    email = request.get_json()['email']
    password = bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
    gender = request.get_json()['gender']

    father_name = request.get_json()['father_name']
    mother_name = request.get_json()['mother_name']
    contact_number = request.get_json()['contact_number']
    emergency_contact_number= request.get_json()['emergency_contact_number']
    age = request.get_json()['age']
    qualification = request.get_json()['qualification']
    
    created = datetime.utcnow()

    user_id = users.insert({
    'hospital_name': hospital_name,
	'first_name' : first_name, 
    'last_name': last_name,
	'email' : email, 
	'password' : password,
    'age' : age,
    'gender' : gender, 
	'created' : created, 
    'father_name':father_name,
    'mother_name':mother_name,
    'contact_number':contact_number,
    'emergency_contact_number':emergency_contact_number,
    'qualification':qualification
    




    # 'address': {
    #     city: city,
    #     state:'Gujarat',
        
    # },
	}),
    print('user_id isisisisisi', user_id)
    # new_user = users.find_one({'_id' : user_id})

    # result = {'email' : new_user['email'] + ' registered'}
    # print('result is ',result)
    return jsonify({'result' : 'user saved'})
	

##################### LOGIN OF HOSPITAL

@app.route('/api/hospital/login', methods=['POST'])
def loginHospital():
    users = mongo.db.doctors
    email = request.get_json()['email']
    password = request.get_json()['password']
    result = ""
	
    response = users.find_one({'email' : email})

    if response:	
        if bcrypt.check_password_hash(response['password'], password):
            access_token = create_access_token(identity = {
			    'hospital_name': response['hospital_name'],
				'email': response['email']}
				)
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid username and password"})            
    else:
        result = jsonify({"result":"No results found"})
    return result


##################### GETTING ALL THE HOSPITAL ONLY NAMES ##########################
@app.route('/api/hospital/list', methods=['GET'])
def get_all_hospital_list():
    user = mongo.db.hospitals
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'hospital_name':field['hospital_name']})
    # *resp = dumps(users)
    return jsonify(result)













##################### GETTING ALL THE USERS ONLY NAMES ##########################
@app.route('/api/users/', methods=['GET'])
def get_all_users():
    user = mongo.db.users
    result = []
    for field in user.find():
        result.append({'_id': str(field['_id']), 'first_name':field['first_name'], 'last_name':field['last_name']})
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
    user=mongo.db.users
    # case_title=request.get_json()['case_title']
    user.find_one_and_update({'_id': ObjectId(id)}, {'$push':{'cases':{'_id':ObjectId(),"case_name":"Case Blah BLah"}}},upsert=False)
    # new_user = user.find_one({'_id': ObjectId(id)})
    # result = {'name': new_user['name']}
    return jsonify({'result': "Success"})
# Deleting any user by ID
@app.route('/api/user/<id>',methods=['DELETE'])
def delete_user(id):
    user=mongo.db.user
    response = user.delete_one({'_id': ObjectId(id)})
    if response.deleted_count == 1:
        result= {'message':'record deleted'}
    else:
        result= {'message':'No record deleted'}

    return jsonify({'result': result})


#USER DETAILS WITH FULL DETAILS

@app.route('/api/user/<id>',methods=['GET'])
def view_details(id):
    user = mongo.db.users
    field = user.find_one({'_id':ObjectId(id)})
    if field:
        output={'first_name':field['first_name'],
        'last_name':field['last_name'],
        'father_name':field['father_name'],
        'mother_name':field['mother_name'],
        'age':field['age'],
        'contact_number':field['contact_number'],        
        'emergency_contact_number':field['emergency_contact_number'],
        'gender':field['gender'],
        'email':field['email'],
        'profile_photo':field['profile_photo']}

    else:
        output = "No such name"
    return jsonify(output)
    








# ############### alll cases of one user

# @app.route('/api/user/cases/<id>',methods=['GET'])
# def view_cases(id):
#     user = mongo.db.users
#     # result = []
#     result = user.find_one({'_id':ObjectId(id)},{'cases': 1,'_id': 0, 'cases.disease': 1, 'cases._id':str('_id')})  ##  result.append({'_id': str(field['_id']),
#     # print(result)
#     # return jsonify(result)

#     resp = json.loads(dumps(result))
#     print(resp)
#     return jsonify(resp)




############### alll cases of one user

@app.route('/api/user/cases/<id>',methods=['GET'])
def view_cases(id):
    user = mongo.db.users
    result = []

    for field in user.find_one({'_id':ObjectId(id)},{'cases': 1,'_id': 0, 'cases.disease': 1, 'cases._id':1})['cases']:
        result.append({'_id':str(field['_id']), 'disease':field['disease']})
    print(result)
    return jsonify(result)


#################### only one case
@app.route('/api/user/cases/case-details/<id>',methods=['GET'])
def view_case_detail(id):
    user = mongo.db.users
    # result = []
    for field in user.find_one({'cases._id':ObjectId(id)},{"cases.$.": 1, '_id': 0})['cases']:
        output = {'case_name':field['case_name'],'disease':field['disease'],'temp':field['temp']}
    print(output)
    return jsonify(output)

    # resp = json.loads(dumps(result))
    # print(resp)
    # return jsonify(resp)

# @app.route('/api/user/cases/<id>',methods=['GET'])
# def view_cases(id):
#     user = mongo.db.users
#     result = []
#     result = user.find_one({ 
#         "$and": [
#             {"_id": ObjectId(id)}, 
#             {"cases": {"$exists": {"case_name":True}}}
#         ] 
#         })
    # for field in user.find({'cases':"case_name"}):
        # result.append({'_id':ObjectId(id), 'case_name':field['case_name']})
    # resp = json.loads(dumps(result))
    # print(resp)
    # return jsonify(resp)



# @app.route('/api/cases/')
#     cases= mongo.db.cases
#     casenumb= request.get_json('')


    # user=mongo.db.user
    # result = []
    # for field in user.find_one({'_id':ObjectId(id)}):
    #     result.append({ 'name':field['name'], 'city':field['city']})
    
    # return jsonify(result)
 



 ##########################################################################################################

 #######################          UPLOAD         ##########################




ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/file-upload', methods=['POST'])
def upload_file():
	# check if the post request has the file part
	if 'file' not in request.files:
		resp = jsonify({'message' : 'No file part in the request'})
		resp.status_code = 400
		return resp
	file = request.files['file']
	if file.filename == '':
		resp = jsonify({'message' : 'No file selected for uploading'})
		resp.status_code = 400
		return resp
	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads', filename))
		# save_filename = (UPLOAD_FOLDER+filename)
		resp = jsonify({'message' : 'File successfully uploaded'})
        # def savefilenametodatabase():
        #     location = mongo.db.users

		resp.status_code = 201
		return resp

    
      
        
	else:
		resp = jsonify({'message' : 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'})
		resp.status_code = 400
		return resp


@app.route('/api/count', methods=['GET'])
def get_all_counts():
    result = []
    users_count = mongo.db.users.count()
    doctors_count = mongo.db.doctors.count()
    hospitals_count = mongo.db.hospitals.count()
    clinics_count = mongo.db.clinics.count()
    medical_store_count = mongo.db.medicalstores.count()

    result={'users_count':users_count,
            'hospitals_count':hospitals_count,
            'doctors_count':doctors_count,
            'clinics_count':clinics_count,
            'medical_store_count':medical_store_count}
    
    return jsonify(result)

@app.errorhandler(404)
def not_found(error=None):
    message = {
        'status':404,
        'message':'Not found blah blah NOT WORKING' + request.url
    }
    resp = jsonify(message)

    resp.status_code = 404

    return resp

if __name__ == "__main__":
    app.run(debug=True)
