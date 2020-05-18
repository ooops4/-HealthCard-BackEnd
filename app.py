import os
import upload
from flask import Flask, jsonify, request, json, redirect, send_from_directory
from flask_pymongo  import PyMongo
from bson.json_util import dumps
import json
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

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)
UPLOAD_FOLDER = 'C:/Users/Blaxtation/Desktop/backend/uploads/'

@app.route('/<path:path>', methods=['GET'])
def static_proxy(path):
  return send_from_directory('./', path)


###########################################################################################
########################            USER API             #################################

########################       LOGIN OF USERS      #################################
@app.route('/api/user/login', methods=['POST'])
def loginUser():
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
				'email': response['email'],
                'first_name' : response['first_name'], 
                'last_name' : response['last_name'],
                'age' : response['age'],
                'gender' : response['gender'], 
                'created' : response['created'], 
                'father_name': response['father_name'],
                'mother_name': response['mother_name'],
                'contact_number': response['contact_number'],
                'emergency_contact_number': response['emergency_contact_number'],
                'blood_group': response['blood_group'],
                'dob': response['dob'],
                'profile_photo': response['profile_photo'],
                'marital_status': response['marital_status'],
                'aadhar_number': response['aadhar_number'],
                'street': response['address']['street'],
                'city': response['address']['city'],
                'state': response['address']['state'],
                'pincode': response['address']['pincode'],
                'landmark': response['address']['landmark']
                
            })
            result = jsonify({"token":access_token})
        else:
            result = jsonify({"error":"Invalid username and password"})            
    else:
        result = jsonify({"result":"No results found"})
    return result


#**********************************************************************************************************************************************************
#**********************************************************************************************************************************************************
########################            ADMIN API             #################################

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
            result = jsonify({"error":"Invalid email and password"})            
    else:
        result = jsonify({"result":"Invalid email and password"})
    return result



######################## ADMIN WILL REGISTER - REGISTRATION OF USERS #################################
@app.route('/api/register', methods=['POST'])
def registerUser():
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
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/'+filename)
        print(save_filename)
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
    age = request.form['age']
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    father_name = request.form['father_name']
    mother_name = request.form['mother_name']
    blood_group = request.form['blood_group']
    marital_status = request.form['marital_status']
    aadhar_number = request.form['aadhar_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    address_landmark = request.form['landmark']
    dob = request.form['dob']
    
    created = datetime.utcnow()
    print(created)

    user_id = users.insert_one({
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
        'blood_group': blood_group,
        'dob': dob,
        'cases': {
                    },
        'marital_status':marital_status,
        'aadhar_number':aadhar_number,
        'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    # new_user = users.find_one({'_id' : user_id})

    # result = {'email' : new_user['email'] + ' registered'}
    # print('result is ',result)
    return jsonify({'result' : 'user saved'})
	



#**********************************************************************************************************************************************************
#**********************************************************************************************************************************************************
########################            CLINICS  API            ##########################

########################       REGISTRATION OF CLINICS      #################################


ALLOWED_EXTENSIONS_CLINICS = set(['pdf'])

def allowed_file_for_clinics(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_CLINICS

@app.route('/api/clinic/register', methods=['POST'])
def registerClinic():
    # check if the post request has the file part
    if 'clinic_document' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['clinic_document']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file_for_clinics(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads/clinicsregistration', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/clinicregistration/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        resp.status_code = 201

    clinic = mongo.db.clinics

    clinic_name = request.form['clinic_name']
    license_number = request.form['license_number']
    established_date = request.form['established_date']
    doctor_name = request.form['doctor_name']
    qualification = request.form['qualification']
    email = request.form['email']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    gender = request.form['gender']
    age = request.form['age']
    dob = request.form['dob']
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    address_landmark = request.form['landmark']
    created = datetime.utcnow()
    print(created)

    user_id = clinic.insert_one({
        'clinic_name' : clinic_name, 
        'license_number' : license_number, 
        'established_date' : established_date, 
        'doctor_name' : doctor_name, 
        'qualification' : qualification, 
        'email' : email, 
        'password' : password,
        'age' : age,
        'gender' : gender,
        'dob': dob,
        'created' : created, 
        'contact_number':contact_number,
        'emergency_contact_number':emergency_contact_number,
        'clinic_document':save_filename,
        'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    return jsonify({'result' : 'user saved'})


##################### GETTING ALL THE CLINICS NAMES ONLY  ##########################
@app.route('/api/clinics/clinic-list', methods=['GET'])
def get_all_clinics_list():
    clinic = mongo.db.clinics
    result = []
    for field in clinic.find():
        result.append({'_id': str(field['_id']), 'clinic_name':field['clinic_name']})
    # *resp = dumps(users)
    return jsonify(result)    
	


##################### GETTING ALL THE CLINIC DETAILS   ##########################
@app.route('/api/clinic/<id>',methods=['GET'])
def view_clinic_details(id):
    clinic = mongo.db.clinics
    field = clinic.find_one({'_id':ObjectId(id)})
    if field:
        output={
                'clinic_name':field['clinic_name'], 
                'license_number' : field['license_number'], 
                'established_date' : field['established_date'], 
                'doctor_name' : field['doctor_name'], 
                'qualification' :field ['qualification'], 
                'email' :field['email'], 
                'age' : field['age'],
                'gender' :field['gender'],
                'dob': field['dob'],
                'created' : field['created'], 
                'contact_number':field['contact_number'],
                'emergency_contact_number':field['emergency_contact_number'],
                'clinic_document':field['clinic_document'],
                'street':field['address']['street'],
                'city': field['address']['city'],
                'state': field['address']['state'],
                'pincode': field['address']['pincode'],
                'landmark': field['address']['landmark']
                }

    else:
        output = "No such Clinic Found"
    print(output)
    return jsonify(output)


#**********************************************************************************************************************************************************
#**********************************************************************************************************************************************************
########################            DOCTOR API            #################################


########################    REGISTRATION OF NEW DOCTOR    #################################
@app.route('/api/doctor/register', methods=['POST'])
def registerDoctor():
    # check if the post request has the file part
    if 'doctor_document' not in request.files:
        resp = jsonify({'message' : 'No file part in the request'})
        resp.status_code = 400
        return resp
    file = request.files['doctor_document']
    if file.filename == '':
        resp = jsonify({'message' : 'No file selected for uploading'})
        resp.status_code = 400
        return resp
    if file and allowed_file_for_clinics(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join('C:/Users/Blaxtation/Desktop/backend/uploads/doctorsregistration', filename))
        save_filename = ('http://127.0.0.1:5000/uploads/doctorsregistration/'+filename)
        print(save_filename)
        resp = jsonify({'message' : 'File successfully uploaded'})
        resp.status_code = 201

    users = mongo.db.doctors

    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    gender = request.form['gender']
    dob = request.form['dob']
    age = request.form['age']
    qualification = request.form['qualification']
    contact_number = request.form['contact_number']
    emergency_contact_number= request.form['emergency_contact_number']
    address_street = request.form['street']
    address_city = request.form['city']
    address_state = request.form['state']
    address_pincode = request.form['pincode']
    address_landmark = request.form['landmark']
    
    created = datetime.utcnow()

    user_id = users.insert({
	'first_name' : first_name, 
	'last_name' : last_name, 
	'email' : email, 
	'password' : password,
    'age' : age,
    'gender' : gender, 
	'created' : created, 
    'contact_number':contact_number,
    'emergency_contact_number':emergency_contact_number,
    'qualification':qualification,
    'dob':dob,
    'doctor_document': save_filename,
    'address': {
                    'street':address_street,
                    'city': address_city,
                    'state': address_state,
                    'pincode': address_pincode,
                    'landmark':address_landmark
                    }
        }),
    print('user_id isisisisisi', user_id)
    return jsonify({'result' : 'user saved'})
	

#####################           LOGIN OF DOCTOR                ##################################

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
            result = jsonify({"token":access_token, "_id": str(response['_id']), 'doctor_name':response['first_name'] })
        else:
            result = jsonify({"error":"Invalid username and password"})            
    else:
        result = jsonify({"result":"Invalid email or password"})
    return result


##################### GETTING ALL THE DOCTORS ONLY NAMES ##########################
@app.route('/api/doctor/doctor-list', methods=['GET'])
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


@app.route('/api/users/emails/', methods=['GET'])
def get_all_users_email():
    user = mongo.db.users
    result = []
    for field in user.find():
        result.append({'email':field['email']})
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
                'email':field['email'],
                'age':field['age'],
                'gender':field['gender'],
                'father_name':field['father_name'],
                'mother_name':field['mother_name'],
                'contact_number':field['contact_number'],        
                'emergency_contact_number':field['emergency_contact_number'],
                'profile_photo':field['profile_photo'],
                'blood_group': field['blood_group'],
                'dob':field['dob'],
                'marital_status':field['marital_status'],
                'aadhar_number':field['aadhar_number'],
                'street':field['address']['street'],
                'city': field['address']['city'],
                'state': field['address']['state'],
                'pincode': field['address']['pincode'],
                'landmark': field['address']['landmark']
                    }

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

############## ADDING A NEW CASE ##################
#updating by <id> details
@app.route('/api/user/<id>', methods=['PUT'])
def add_new_case_to_user(id):
    user=mongo.db.users
    # case_title=request.get_json()['case_title']
    user.find_one_and_update({'_id': ObjectId(id)}, {'$push':{'cases':{'_id':ObjectId(),"case_name":"Case Blah BLah"}}},upsert=False)
    # new_user = user.find_one({'_id': ObjectId(id)})
    # result = {'name': new_user['name']}
    return jsonify({'result': "Success"})




############### alll cases of one user ########################

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
