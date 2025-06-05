from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_
from sqlalchemy.sql import text
import uuid
from werkzeug.utils import secure_filename

from tensorflow.keras.models import load_model
import cv2
import numpy as np

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
jwt = JWTManager(app)
app.config["SQLALCHEMY_DATABASE_URI"]= "postgresql://neondb_owner:npg_TAHSzsn6Zo7Y@ep-dawn-recipe-a5507yja-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Setup upload folder for eye scans
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

class Users(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(50), primary_key=True,nullable=False)
    username = db.Column(db.String(50), unique=True,nullable=False)
    email = db.Column(db.String(90), unique=True,nullable=False)
    password = db.Column(db.String(90),nullable=False)
    age = db.Column(db.String(50))
    gender = db.Column(db.String(15))
    created_at = db.Column(db.DateTime,default=datetime.utcnow,nullable=False)

class Scans(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.String(50), primary_key = True,nullable=False)
    image_path = db.Column(db.String(2000000),nullable=False)
    prediction = db.Column(db.String(50),nullable=False)
    confidence = db.Column(db.String(50),nullable=False)
    severity = db.Column(db.String(50),nullable=False)
    created_at = db.Column(db.DateTime,default=datetime.utcnow,nullable=False)
    user_id = db.Column(db.String(50), db.ForeignKey("users.id"),nullable=False)
    user = db.relationship("Users",backref = "scans",primaryjoin="Users.id==Scans.user_id")

with app.app_context():
    db.create_all()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Authentication routes
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password') or not data.get('username'):
        return jsonify({"message": "Missing required fields"}), 400
    
    user = db.session.execute(db.select(Users).where(Users.email==str(text(data.get('email'))))).scalars().all()
    
    if user:
        return jsonify({"message": "User with this email already exists"}), 409
    
    user_id = str(uuid.uuid4())
    hashed_password = str(text((data.get('password'))))
    username = str(text(data.get('username')))
    email = str(text(data.get('email')))
    age = str(text(data.get('age')))
    gender = str(text(data.get('gender')))

    new_user = Users(id=user_id,username=username,email=email,password=hashed_password,age=age,gender=gender)
    
    db.session.add(new_user)
    db.session.commit()
    access_token = create_access_token(identity=user_id)
    user_dict = {'id':new_user[0].id,'username':new_user[0].username,'email':new_user[0].email}
    
    return jsonify({
        "message": "User created successfully",
        "user": user_dict,
        "token": access_token
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"message": "Missing email or password"}), 400
    
    user = db.session.execute(db.select(Users).where(Users.email==str(text(data.get('email'))))).scalars().all()
    
    if not user or not (user[0].password == data.get('password')):
        return jsonify({"message": "Invalid email or password"}), 401
    
    user_dict = {'id':user[0].id,'username':user[0].username,'email':user[0].email}
    
    access_token = create_access_token(identity=user[0].id)
    
    return jsonify({
        "message": "Login successful",
        "user": user_dict,
        "token": access_token
    }), 200

@app.route('/api/validate-token', methods=['GET'])
@jwt_required()
def validate_token():
    current_user_id = get_jwt_identity()
    
    
    user = db.session.execute(db.select(Users).where(Users.id==str(text(current_user_id)))).scalars().all()
    
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    
    user_dict = {'id':user[0].id,'username':user[0].username,'email':user[0].email}
    
    return jsonify(user_dict), 200

# Scan routes
@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_scan():
    c = ['Normal','Diabetic Retropheny','Glucoma','Cataract']
    current_user_id = get_jwt_identity()
    
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Create a unique filename with user_id and timestamp
        unique_filename = f"{current_user_id}_{int(datetime.now().timestamp())}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        image = cv2.imread(file_path)
        image = cv2.resize(image,(224,224))
        image = image.astype('float32') / 255.0
        image = np.expand_dims(image, -1)
        image = np.expand_dims(image, 0)
        
        cataract_model = load_model('cataract.h5')
        glaucoma_model = load_model('glaucoma.h5')
        dr_model = load_model('dr.h5')


        res = cataract_model.predict(image)
        res1 = glaucoma_model.predict(image)
        res2 = dr_model.predict(image)
        print("Cataract",res)
        print("Glucoma",res1)
        print("DR",res2)
        if(res <= 0.5 or res1 <= 0.5 or res2 <= 0.5):
            prediction = c[0]
            confidence = 0
        
        elif(res >= 0.5 or res1 <= 0.5 or res2 <= 0.5):
            prediction = c[3]
            confidence = abs(res*100)
            
        elif(res <= 0.5 or res1 >= 0.5 or res2 <= 0.5):
            prediction = c[2]
            confidence = abs(res1*100)
            
        elif(res <= 0.5 or res1 <= 0.5 or res2 <= 0.5):
            prediction = c[1]
            confidence = abs(res2*100)

        severity = None
        # Save scan to database
        scan_id = str(uuid.uuid4())
        scan = Scans(id=str(text(scan_id)),user_id=str(text(current_user_id)),
                     image_path=str(text(request.form['filePath'])),prediction=str((prediction)),confidence=str((confidence)),severity=str((severity)))
        
        db.session.add(scan)
        db.session.commit()

        scan_details = {'id':scan.id,'user_id':scan.user_id,'imagepath':scan.image_path,'pred':scan.prediction,'conf':scan.confidence,'severity':scan.severity,'datetime':scan.created_at}
        return jsonify({
            "message": "Scan uploaded and analyzed successfully",
            "scan": scan_details
        }), 201
    
    return jsonify({"message": "File type not allowed"}), 400

@app.route('/api/scans', methods=['GET'])
@jwt_required()
def get_scans():
    current_user_id = get_jwt_identity()
    
    # scans = conn.execute('SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC', (current_user_id,)).fetchall()
    scans = db.session.execute(db.select(Scans).where(Scans.user_id==current_user_id)).scalars().fetchall()
    
    return jsonify({
        "scans": [{'id':scan.id,'user_id':scan.user_id,'imagepath':scan.image_path,'pred':scan.prediction,'conf':scan.confidence,'severity':scan.severity,'datetime':scan.created_at} 
                  for scan in scans]
    }), 200

@app.route('/api/scans/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan(scan_id):
    current_user_id = get_jwt_identity()
    
    scan = db.session.execute(db.select(Scans).where(Scans.id==scan_id).where(Users.id==current_user_id)).scalars().all()
    print(scan)
    if not scan:
        return jsonify({"message": "Scan not found"}), 404
    
    scan_details = {'id':scan[0].id,'user_id':scan[0].user_id,'imagepath':scan[0].image_path,'pred':scan[0].prediction,'conf':scan[0].confidence,'severity':scan[0].severity,'datetime':scan[0].created_at}
        

    return jsonify(scan_details), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)