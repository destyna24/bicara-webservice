from flask import Flask, Blueprint, request, jsonify
from flask_mail import Mail, Message
from flask_restx import Resource, Api, Namespace, reqparse
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.datastructures import FileStorage
from datetime import date, datetime, timedelta
from json import dumps
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import mediapipe as mp
from mediapipe.framework.formats import landmark_pb2
from joblib import load
import keras
from tensorflow.keras.models import load_model
import jwt
import base64
import cv2
import numpy as np
import tensorflow as tf
import random
import time
import os
import imghdr
import re
import warnings
import pytz
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async_mode = 'None'
app = Flask(__name__)
socketio = SocketIO(app, async_mode=None)
CORS(app)
TEMP_FOLDER = './temp/' #upload folder
app.config['TEMP_FOLDER'] = TEMP_FOLDER

#initialization database mysql
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/bicara_db"  #database name
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
db = SQLAlchemy(app)

#Initialization email mailtrap
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '0b6e4d62784525'
app.config['MAIL_PASSWORD'] = '7705b93d4d5cf3'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

local_timezone = pytz.timezone('Asia/Jakarta')
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

#create class to initialization table form db
#model table m_users
class User(db.Model):
    __tablename__ = 'm_users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=True)
    gender_id = db.Column(db.Integer, nullable=True)
    email = db.Column(db.String(50), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    verify_otp = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False)

#model table m_gender
class Gender(db.Model):
    __tablename__ = 'm_gender'
    id = db.Column(db.Integer, primary_key=True)
    gender = db.Column(db.String(10), nullable=False)

#model table m_auth
class Auth(db.Model):
    __tablename__ = 'm_auth'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    login_at = db.Column(db.DateTime, nullable=False)
    logout_at = db.Column(db.DateTime, nullable=False)
    token = db.Column(db.String(1000), nullable=True)
    token_expired_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False)

#model table m_auth
class Otp(db.Model):
    __tablename__ = 'm_otp'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    otp = db.Column(db.String(256), nullable=True)
    otp_expired_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False)

#model table t_feedback
class Feedback(db.Model):
    __tablename__ = 't_feedback'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    feedback = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, server_default=func.current_timestamp())

blueprint = Blueprint('api', __name__, url_prefix='/api/bicara/v1') #localhost + /api + route
app.register_blueprint(blueprint) #swager documentation api

#desc auth when login => save baerer token jwt
authorizations = {
    "Bearer": {
        "type": "apiKey", 
        "name": "Authorization", 
        "in": "header",
        "description": "Gunakan prefix <b><i>Bearer</b></i>, Contoh <b>Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIx</b>"
        }
    }

#initialization for swager docs api
api = Api(
    app,
    authorizations=authorizations,
    title='ApiDocs',
    version='1.0',
    description='Bicara API Documentation',
    prefix='/api/bicara/v1'
    )

#to decode base64
SECRET_KEY = "V2hhdEV2ZXJZb3VXYW50IQ=="
ISSUER = "bXlGbGFza1dlYlNlcnZpY2VCaWNhcmE="
AUDIENCE_MOBILE = "bXlNb2JpbGVBcHA="
API_KEY = "aW5pYXBpa2V5bG9o"

#create function to decode jwt
def decode(jwtToken):
    # payload
    payload = jwt.decode(
        jwtToken,
        SECRET_KEY,
        audience = [AUDIENCE_MOBILE],
        issuer = ISSUER,
        algorithms = ['HS256'],
        options = {"require": ["aud", "iss", "iat", "exp"]}
    )
    return payload

#create function for validation token valid and expires > now = expired
def isTokenValid(token):
    now = datetime.now(local_timezone)
    logging.debug("Waktu saat ini: %s", now)

    try:
        # Decode token
        payload = decode(token)
        logging.debug("Payload: %s", payload)

        # Cek apakah exp < now
        if 'exp' in payload:
            exp = datetime.fromtimestamp(payload['exp'], tz=local_timezone)
            logging.debug("Waktu exp: %s", exp)
            if now > exp:
                return False
        else:
            return False

        return True

    except jwt.ExpiredSignatureError:
        logging.error("Token expired")
        return False
    except jwt.InvalidTokenError:
        logging.error("Invalid token")
        return False

def sendMail(email, otp):
    msg = Message('Verifkasi OTP Bi-Cara', 
                  sender=('Aplikasi Bi-Cara', 'bicara@yopmail.com'), 
                  recipients=[email])
    msg.body = "Kode verifikasi OTP kamu adalah " + otp
    mail.send(msg)
    return "OTP Sent to" + email

print(f"Keras version: {keras.__version__}")
print(f"TensorFlow version: {tf.__version__}")

#### API ####

# Load scaler and LSTM model
scaler = load('./model/scalerMinmax.pkl')
model = load_model('./model/modelTerbaruuu3.h5')

# Import MediaPipe Hand Landmarker
BaseOptions = mp.tasks.BaseOptions
HandLandmarker = mp.tasks.vision.HandLandmarker
HandLandmarkerOptions = mp.tasks.vision.HandLandmarkerOptions
VisionRunningMode = mp.tasks.vision.RunningMode

# MediaPipe Hand Landmarker initialization and result retrieval
class LandmarkerAndResult:
    def __init__(self):
        self.result = mp.tasks.vision.HandLandmarkerResult
        self.landmarker = mp.tasks.vision.HandLandmarker
        self.createLandmarker()
    
    def createLandmarker(self):
        options = HandLandmarkerOptions(
            base_options=BaseOptions(model_asset_path='./model/hand_landmarker.task'),
            running_mode=VisionRunningMode.IMAGE,
            num_hands=2)
        
        self.landmarker = self.landmarker.create_from_options(options)

    def detect(self, frame):
        rgb_image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb_image)
        self.result = self.landmarker.detect(image=mp_image)
        
    def close(self):
        self.landmarker.close()

# Fungsi untuk mengekstrak koordinat landmark dari hasil deteksi MediaPipe
def extractCoordinates(resultDetect):
    coordinates = []
    hand_landmarks_list = resultDetect.hand_landmarks
    handedness_list = resultDetect.handedness
    
    for idx in range(len(hand_landmarks_list)):
        hand_landmarks = hand_landmarks_list[idx]
        handedness = handedness_list[idx]
        hand_label = handedness[0].category_name
        coordinates.append(hand_label)
        for i, landmark in enumerate(hand_landmarks):
            coordinates.append(landmark.x)
            coordinates.append(landmark.y)
            coordinates.append(landmark.z)
    return coordinates

# Fungsi untuk preprocessing landmark sebelum prediksi menggunakan model LSTM
def preprocess_landmarks(coordinates, scaler):
        
    for i, val in enumerate(coordinates):
        if val == 'Right':
            coordinates[i] = 1
        elif val == 'Left':
            coordinates[i] = 0
            
    # Ubah data ke dalam tipe numerik
    coordinates = [float(val) for val in coordinates]
        
    newData = np.array([coordinates])
    
    newData_scaled = scaler.transform(newData)
    
    newDataReshape = newData.reshape(newData_scaled.shape[0], newData_scaled.shape[1], 1)
    
    #print(newDataReshape.shape)
        
    return newDataReshape

def split_coordinates(coordinates):
    list1 = coordinates[:64]
    list2 = coordinates[64:]

    return list1, list2

# Draw landmarks on the image
def draw_landmarks_on_image(rgb_image, detection_result: mp.tasks.vision.HandLandmarkerResult):
    try:
        if detection_result.hand_landmarks == []:
            return rgb_image
        else:
            hand_landmarks_list = detection_result.hand_landmarks
            annotated_image = np.copy(rgb_image)

            for idx in range(len(hand_landmarks_list)):
                hand_landmarks = hand_landmarks_list[idx]
                
                hand_landmarks_proto = landmark_pb2.NormalizedLandmarkList()
                hand_landmarks_proto.landmark.extend([
                    landmark_pb2.NormalizedLandmark(x=landmark.x, y=landmark.y, z=landmark.z) for landmark in hand_landmarks])
                mp.solutions.drawing_utils.draw_landmarks(
                   annotated_image,
                   hand_landmarks_proto,
                   mp.solutions.hands.HAND_CONNECTIONS,
                   mp.solutions.drawing_styles.get_default_hand_landmarks_style(),
                   mp.solutions.drawing_styles.get_default_hand_connections_style())
            return annotated_image
    except:
        return rgb_image

# Initialize MediaPipe Hand Landmarker
hand_landmarker = LandmarkerAndResult()

@api.route('/detect_landmarks', methods=['POST'])
class Detect_Landmarks_Route(Resource):
    def post(self):
        try:
            # Ambil file gambar dari request
            if 'image' not in request.files:
                return {"error": "Tidak ada file gambar yang diunggah"}, 400

            image_file = request.files['image']

            # Konversi dari file ke gambar
            imgdata = cv2.imdecode(np.frombuffer(image_file.read(), np.uint8), cv2.IMREAD_COLOR)

            # Cek ukuran gambar
            height, width, _ = imgdata.shape
            print(f"Ukuran gambar: {width}x{height}")

            # Cek orientasi
            if height > width:
                print("Gambar dalam orientasi potret (portrait).")
            else:
                print("Gambar dalam orientasi lanskap (landscape).")

            # Proses gambar dan deteksi landmark tangan
            hand_landmarker.detect(imgdata)
            resultDetect = hand_landmarker.result
            print("hasil landmark: ", resultDetect)

            if resultDetect is not None and hasattr(resultDetect, 'hand_landmarks'):
                print("halo")
                # Ubah hasil landmark menjadi data yang dapat digunakan
                coordinates = extractCoordinates(resultDetect)
                print("Koordinat: ", coordinates)

                preLandmarks = None
                frameImg = imgdata  # pastikan frame diinisialisasi dengan gambar asli
                frame = None
                if len(coordinates) > 0 and len(coordinates) <= 64:
                    preLandmarks = preprocess_landmarks(coordinates, scaler)
                    frame = draw_landmarks_on_image(frameImg, resultDetect)
                elif len(coordinates) >= 64:
                    list1, list2 = split_coordinates(coordinates)
                    preLandmarks = preprocess_landmarks(list1, scaler)
                    preLandmarks = preprocess_landmarks(list2, scaler)
                    frame = draw_landmarks_on_image(frameImg, resultDetect)
                    frame = draw_landmarks_on_image(frameImg, resultDetect)
                else:
                    return {"noLabel": "Tidak ada landmark tangan yang terdeteksi"}, 202
                frame = np.array(frame, dtype=np.uint8)
                # print(frame)
                if preLandmarks is not None:
                    # Predict using LSTM model
                    prediction = model.predict(preLandmarks)
                    print("Prediksi: ", prediction)

                    # Mengonversi output prediksi menjadi label kelas
                    predicted_class = np.argmax(prediction, axis=1)
                    print("Kelas yang diprediksi: ", predicted_class)

                    percentage_probabilities = prediction[0][predicted_class] * 100

                    # Kembalikan hasil prediksi
                    label = ""
                    if predicted_class == 0:
                        label = "an"
                        print(label)
                    elif predicted_class == 1:
                        label = "atur"
                        print(label)
                    elif predicted_class == 2:
                        label = "bagaimana"
                        print(label)
                    elif predicted_class == 3:
                        label = "daftar"
                        print(label)
                    elif predicted_class == 4:
                        label = "dengan"
                        print(label)
                    elif predicted_class == 5:
                        label = "dokter"
                        print(label)
                    elif predicted_class == 6:
                        label = "jadwal"
                        print(label)
                    elif predicted_class == 7:
                        label = "kan"
                        print(label)
                    elif predicted_class == 8:
                        label = "kapan"
                        print(label)
                    elif predicted_class == 9:
                        label = "me"
                        print(label)
                    elif predicted_class == 10:
                        label = "minum"
                        print(label)
                    elif predicted_class == 11:
                        label = "obat"
                        print(label)
                    elif predicted_class == 12:
                        label = "proses"
                        print(label)
                    elif predicted_class == 13:
                        label = "saya"
                        print(label)
                    else:
                        label = "Tidak dikenal"
                        print(label)

                    _, buffer = cv2.imencode('.jpg', frame)                    
                    # print("123")
                    landmarked_image = base64.b64encode(buffer).decode('utf-8')
                    # print("456")
                    # print(landmarked_image)

                    return {
                        'label': label,
                        'probability': percentage_probabilities.tolist(),
                        'landmarked_image': landmarked_image
                    }, 201
                else:
                    return {"error": "Tidak ada landmark tangan yang diproses"}, 400
            else:
                return {"error": "Tidak ada landmark tangan yang terdeteksi"}, 400

        except Exception as e:
            return {"error": str(e)}, 400

# API Register (Only Request Body)
parser4Register = reqparse.RequestParser()
parser4Register.add_argument('name', type=str, location='json', required=True, help='Masukkan Nama')
parser4Register.add_argument('gender_id', type=int, location='json', required=True, help='Masukkan Id Gender')
parser4Register.add_argument('email', type=str, location='json', required=True, help='Masukkan Email')
parser4Register.add_argument('password', type=str, location='json', required=True, help='Masukkan Password')

@api.route('/register',methods=['POST']) #method POST
class Register_Route(Resource):
    @api.expect(parser4Register, validate=True)
    @api.response(201, 'Created')
    def post(self):
        args = parser4Register.parse_args()
        email = args['email']
        
        now = datetime.now(local_timezone)
        print("waktu saat ini", now)

        try:
            with db.session.begin():
                userCount = User.query.filter_by(email=email).count()
                if userCount > 0:
                    return {'message':'Email sudah digunakan'}, 400
                user = User()
                user.name = args['name']
                user.gender_id = args['gender_id']
                user.email = email
                user.password = generate_password_hash(args['password'])
                db.session.add(user)
                db.session.flush()
                #generate otp random 4 digit
                otp = random.randint(1000, 9999)
                print("Ini kode otp",otp)
                otp_expired_at = now + timedelta(minutes=5)
                # add otp to m_otp, set expired otp
                mOtp = Otp()
                mOtp.user_id = user.id
                mOtp.otp = generate_password_hash(str(otp))
                mOtp.otp_expired_at = otp_expired_at
                # add table m_otp
                db.session.add(mOtp)
                #send code otp to email
                sendMail(email, str(otp))
        except Exception as e:
            #otomatis rollback if error on transaction
            return {'message': str(e)}, 500

        return {
            'message' : 'Berhasil mengirim OTP ke email '+ user.email,
            'data' : {
                'user_id' : user.id,
                'otp_expired_at': mOtp.otp_expired_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        }, 201
    
#API Resend OTP (Headers + Request Body)
parser4ResendOtp = reqparse.RequestParser()
parser4ResendOtp.add_argument('api-key', type=str, location='headers', required=True, help='Masukkan API-KEY')
parser4ResendOtp.add_argument('user_id', type=int, location='json', required=True, help='Masukkan User Id')

@api.route('/resend-otp') # method POST
class ResendOTP_Route(Resource):
    @api.expect(parser4ResendOtp, validate=True)
    @api.response(200, 'OK')
    def post(self):
        args = parser4ResendOtp.parse_args()
        apiKey = args['api-key']
        user_id = args['user_id']

        # Dapatkan waktu saat ini dengan informasi zona waktu
        now = datetime.now(local_timezone)
        logger.info("Waktu saat ini: %s", now)

        # Checking for API key validity
        if API_KEY != apiKey:
            return {'message': 'API KEY Invalid!'}, 400

        try:
            # Check OTP and its expiration
            checkOtp = Otp.query.filter(Otp.user_id == user_id).first()
            if not checkOtp:
                return {'message': 'Kamu belum registrasi, silahkan lakukan registrasi'}, 400

            # Konversi otp_expired_at ke waktu lokal jika tidak memiliki informasi zona waktu
            if checkOtp.otp_expired_at.tzinfo is None:
                checkOtp.otp_expired_at = local_timezone.localize(checkOtp.otp_expired_at)

            if checkOtp.otp_expired_at > now:
                return {'message': 'OTP sudah kami kirim, cek email yuk'}, 400

            # Fetch user email
            user = User.query.filter_by(id=user_id).first()
            if not user:
                return {'message': 'User tidak ditemukan'}, 400
            
            email = user.email
            logger.info("User email: %s", email)

            # Generate random 4-digit OTP
            otp = random.randint(1000, 9999)
            logger.info("Ini kode OTP: %d", otp)
            otp_expired_at = now + timedelta(minutes=5)

            # Update OTP record
            checkOtp.otp = generate_password_hash(str(otp))
            checkOtp.otp_expired_at = otp_expired_at
            checkOtp.updated_at = now

            # Commit the session
            db.session.commit()

            # Send OTP to email
            sendMail(email, str(otp))
            logger.info("OTP sent to email: %s", email)

        except Exception as e:
            logger.error("Error: %s", str(e))
            return {'message': str(e)}, 500

        return {
            'message': 'Berhasil Resend OTP',
            'data': {
                'otp_expired_at': otp_expired_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': checkOtp.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        }, 200

# API Verify OTP (Headers + Request Body)
parser4VerifyOtp = reqparse.RequestParser()
parser4VerifyOtp.add_argument('api-key', type=str, location='headers', required=True, help='Masukkan API-KEY')
parser4VerifyOtp.add_argument('otp', type=str, location='json', required=True, help='Masukkan Kode OTP')
parser4VerifyOtp.add_argument('user_id', type=int, location='json', required=True, help='Masukkan User Id')

@api.route('/verify-otp') #method POST
class VerifyOtp_Route(Resource):
    @api.expect(parser4VerifyOtp, validate=True)
    @api.response(200, 'Verified')
    def post(Self):
        args = parser4VerifyOtp.parse_args()
        apiKey = args['api-key']
        otp = args['otp']
        user_id = args['user_id']
        
        now = datetime.now(local_timezone)
        print("waktu saat ini", now)

        #checking for api key is valid
        if API_KEY != apiKey:
            return {'message':'API KEY Invalid!'}, 400
        
        try:
            #start transaction
            with db.session.begin():
        
                #check code otp or otp_expired_at < now
                checkOtp = Otp.query.filter(Otp.user_id==user_id).first()
                if not check_password_hash(checkOtp.otp, otp):
                    return {'message': 'OTP Invalid'}, 400
                if checkOtp.otp_expired_at < datetime.now():
                    return {'message': 'OTP Expired!'}, 400
                        
                #get user by user_id associated with the OTP
                user = User.query.get(checkOtp.user_id)
                if not user:
                    return {'message': 'User not found!'}, 400
                
                #update table m_users col verify_otp is true when OTP.user_id == User.id
                user.verify_otp = True
                user.updated_at = now
                
                #get data new user
                user_data = {
                    'user_id': user.id,
                    'nama': user.name,
                    'email': user.email,
                    'verify_otp': user.verify_otp,
                    'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'updated_at': user.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                }
                print(user_data)

        except Exception as e:
            #rollback here
            return {'message': str(e)}, 500

        return {
            'message' : 'Berhasil Verifikasi OTP',
            'data' : user_data
        }, 201

# API Login (Headers + Request Body)
parser4Login = reqparse.RequestParser()
parser4Login.add_argument('api-key', type=str, location='headers', required=True, help='Masukkan API-KEY')
parser4Login.add_argument('email', type=str, location='json', required=True, help='Masukkan Email')
parser4Login.add_argument('password', type=str, location='json', required=True, help='Masukkan Password')

@api.route('/login') #method POST
class Login_Route(Resource):
    @api.expect(parser4Login, validate=True)
    @api.response(200, 'OK')
    def post(self):
        args = parser4Login.parse_args()
        email = args['email']
        password = args['password']
        apiKey = args['api-key']
        
        now = datetime.now(local_timezone)
        print("waktu saat ini", now)

        #checking for api key is valid
        if API_KEY != apiKey:
            return {'message':'API KEY Invalid!'}, 400
        
        try:
            #start transaction
            with db.session.begin():

                #check user filter by email
                user = User.query.filter_by(email=email).first()

                if not user:
                    return {'message':'Kamu belum daftar, yuk daftar dulu'}, 400
                
                # Verify password
                if not check_password_hash(user.password, password):
                    return {'message': 'Password yang kamu masukkan salah'}, 400

                #set expired token
                exp = now + timedelta(hours=5)
                print("waktu exp: ", exp)

                payload = {
                    'req_body' : str(user.id) + user.name + str(user.gender_id) + user.email + user.password,
                    'aud': AUDIENCE_MOBILE,
                    'iss': ISSUER,
                    'iat': int(time.time()),
                    'exp': exp
                }

                #create token jwt
                token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
                print("ini token jwt: ", token)
                print("panjang token", len(token))

                #check user_id on table m_auth
                mAuth = Auth.query.filter_by(user_id=user.id).first()
                if not mAuth:
                    mAuth = Auth()
                    mAuth.user_id = user.id
                    mAuth.token = token
                    mAuth.token_expired_at = exp
                    mAuth.login_at = now
                    mAuth.created_at = now
                    #add table m_auth
                    db.session.add(mAuth)
                else:
                    mAuth.token = token
                    mAuth.token_expired_at = exp
                    mAuth.login_at = now
                    mAuth.updated_at = now

                # Get data user
                user_data = {
                    'user_id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'login_at' : mAuth.login_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'created_at': mAuth.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'updated_at': mAuth.updated_at.strftime('%Y-%m-%d %H:%M:%S') if mAuth.updated_at else None
                }
                print(user_data)
        
        except Exception as e:
            #rollback here
            return {'message': str(e)}, 500

        return {
            'message' : 'Berhasil Login',
            'token' : mAuth.token,
            'data' : user_data
        }, 201
    

@api.route('/check_token')
class C_Token_Route(Resource):
    @api.doc(security='Bearer')
    @api.response(200, 'OK')
    def get(self):
        auth = request.headers.get('Authorization')
        jwtToken = auth[7:]
        print(jwtToken)

        is_valid = isTokenValid(jwtToken)

        if is_valid:
            return {
                'message' : 'Token valid!'
            }, 200
        else:
            return {'message': 'Token tidak valid, silahkan masuk dulu mom'}, 401

# API Get Profile
parser4Profile = reqparse.RequestParser()
parser4Profile.add_argument('user_id', type=int, location='args', required=True, help='Masukkan User Id')

@api.route('/get-profile')
class GetProfile_Route(Resource):
    @api.expect(parser4Profile, validate=True)
    @api.doc(security='Bearer')
    @api.response(200, 'OK')
    def get(self):
        auth = request.headers.get('Authorization')
        jwtToken = auth[7:]
        args = parser4Profile.parse_args()
        user_id = args['user_id']

        is_valid = isTokenValid(jwtToken)
        print(is_valid)
        if is_valid:
            getUser = User.query.filter_by(id=user_id).first()
            gender_id = getUser.gender_id
            gender = Gender.query.filter_by(id=gender_id).first()

            return {
                'data' : {
                    'user_id' : getUser.id,
                    'name' : getUser.name,
                    'email' : getUser.email,
                    'gender' : gender.gender
                }
            }, 200
        else:
            return {'message': 'Token tidak valid, silahkan masuk dulu'}, 401

# API Edit Profile
parser4EditProfile = reqparse.RequestParser()
parser4EditProfile.add_argument('user_id', type=int, location='json', required=True, help='Masukkan User Id')
parser4EditProfile.add_argument('name', type=str, location='json', required=True, help='Masukkan Nama')
parser4EditProfile.add_argument('gender', type=int, location='json', required=True, help='Masukkan Gender')

@api.route('/edit-profile')
class EditProfile_Route(Resource):
    @api.expect(parser4EditProfile, validate=True)
    @api.doc(security='Bearer')
    @api.response(200, 'OK')
    def put(self):
        auth = request.headers.get('Authorization')
        jwtToken = auth[7:]
        args = parser4EditProfile.parse_args()
        user_id = args['user_id']
        name = args['name']
        gender = args['gender']

        now = datetime.now(local_timezone)
        print("waktu saat ini", now)

        is_valid = isTokenValid(jwtToken)
        if is_valid:
            getUser = User.query.filter_by(id=user_id).first()
            getUser.name = name
            getUser.gender = gender
            getUser.updated_at = now
            db.session.commit()

            return {
                'message' : 'Berhasil update data user',
                'data' : {
                    'name' : getUser.name,
                    'gender' : getUser.gender,
                    'updated_at' : getUser.updated_at.strftime('%Y-%m-%d %H:%M:%S')
                }
            }, 200
        else:
            return {'message': 'Token tidak valid, silahkan masuk dulu'}, 401
        
# API check email
parser4CheckMail = reqparse.RequestParser()
parser4CheckMail.add_argument('api-key', type=str, location='headers', required=True, help='Masukkan API-KEY')
parser4CheckMail.add_argument('email', type=str, location='args', required=True, help='Masukkan Email')

@api.route('/check-email')
class EditPassword_Route(Resource):
    @api.expect(parser4CheckMail, validate=True)
    @api.response(200, 'OK')
    def get(self):
        args = parser4CheckMail.parse_args()
        email = args['email']
        apiKey = args['api-key']

        now = datetime.now(local_timezone)
        print("waktu saat ini", now)

        #checking for api key is valid
        if API_KEY != apiKey:
            return {'message':'API KEY Invalid!'}, 400
        
        getUser = User.query.filter_by(email=email).first()
        if not getUser:
            return {'message':'Email belum terdaftar'}, 300

        return {
            'user_id' : getUser.id,
        }, 200

# Check pass lama
parser4CheckPass = reqparse.RequestParser()
parser4CheckPass.add_argument('user_id', type=str, location='args', required=True, help='Masukkan User Id')
parser4CheckPass.add_argument('check_pass', type=str, location='args', required=True, help='Masukkan Password Lama')

@api.route('/check_pass')
class CheckPass(Resource):
    @api.expect(parser4CheckPass, validate=True)
    @api.response(200, 'OK')
    def get(self):
        args = parser4CheckPass.parse_args()
        user_id = args['user_id']
        check_pass = args['check_pass']
        
        #check user filter by user_id
        user = User.query.filter_by(id=user_id).first()
        # Verify password
        if not check_password_hash(user.password, check_pass):
            return {'message': 'Password yang kamu masukkan salah'}, 400
        return {
            'message' : 'Berhasil check password lama'
        }, 200

# API Edit Pass
parser4EditPassNoAuth = reqparse.RequestParser()
parser4EditPassNoAuth.add_argument('api-key', type=str, location='headers', required=True, help='Masukkan API-KEY')
parser4EditPassNoAuth.add_argument('user_id', type=int, location='json', required=True, help='Masukkan Email')
parser4EditPassNoAuth.add_argument('new_pass', type=str, location='json', required=True, help='Masukkan Password Baru')
parser4EditPassNoAuth.add_argument('confirm_pass', type=str, location='json', required=True, help='Konfirmasi Password Baru')

@api.route('/edit-password-no-auth')
class EditPassword_Route(Resource):
    @api.expect(parser4EditPassNoAuth, validate=True)
    @api.response(200, 'OK')
    def put(self):
        args = parser4EditPassNoAuth.parse_args()
        user_id = args['user_id']
        new_pass = args['new_pass']
        confirm_pass = args['confirm_pass']
        apiKey = args['api-key']

        now = datetime.now(local_timezone)
        print("waktu saat ini", now)

        #checking for api key is valid
        if API_KEY != apiKey:
            return {'message':'API KEY Invalid!'}, 400

         #check new pass and confirm pass is same
        if new_pass != confirm_pass:
            return {'message':'Password baru tidak sama'}, 400
        
        getUser = User.query.filter_by(id=user_id).first()
        getUser.password = generate_password_hash(new_pass)
        getUser.updated_at = now
        db.session.commit()

        return {
            'message' : 'Berhasil ubah password',
            'user_id' : getUser.id,
            'updated_at' : getUser.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }, 200
        
# API Edit Pass
parser4EditPassword = reqparse.RequestParser()
parser4EditPassword.add_argument('user_id', type=int, location='json', required=True, help='Masukkan User Id')
parser4EditPassword.add_argument('new_pass', type=str, location='json', required=True, help='Masukkan Password Baru')
parser4EditPassword.add_argument('confirm_pass', type=str, location='json', required=True, help='Konfirmasi Password Baru')

@api.route('/edit-password')
class EditPassword_Route(Resource):
    @api.expect(parser4EditPassword, validate=True)
    @api.doc(security='Bearer')
    @api.response(200, 'OK')
    def put(self):
        auth = request.headers.get('Authorization')
        jwtToken = auth[7:]
        args = parser4EditPassword.parse_args()
        user_id = args['user_id']
        new_pass = args['new_pass']
        confirm_pass = args['confirm_pass']

        now = datetime.now(local_timezone)
        print("waktu saat ini", now)

        is_valid = isTokenValid(jwtToken)
        if is_valid:

            #check new pass and confirm pass is same
            if new_pass != confirm_pass:
                return {'message':'Password baru tidak sama'}, 400
            
            getUser = User.query.filter_by(id=user_id).first()
            getUser.password = generate_password_hash(new_pass)
            getUser.updated_at = now
            db.session.commit()

            return {
                'message' : 'Berhasil ubah password',
                'user_id' : getUser.id,
                'updated_at' : getUser.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            }, 200
        else:
            return {'message': 'Token tidak valid, silahkan masuk dulu'}, 401

 # API Edit Pass
parser4Feedback = reqparse.RequestParser()
parser4Feedback.add_argument('user_id', type=int, location='json', required=True, help='Masukkan User Id')
parser4Feedback.add_argument('feedback', type=str, location='json', required=True, help='Masukkan Feedback')

@api.route('/feedback')
class Feedback_Route(Resource):
    @api.expect(parser4Feedback, validate=True)
    @api.doc(security='Bearer')
    @api.response(200, 'OK')
    def post(self):
        auth = request.headers.get('Authorization')
        jwtToken = auth[7:]
        args = parser4Feedback.parse_args()
        user_id = args['user_id']
        feedback = args['feedback']

        now = datetime.now(local_timezone)
        print("waktu saat ini", now)

        is_valid = isTokenValid(jwtToken)
        if is_valid:
            
            tFeedback = Feedback()
            tFeedback.user_id = user_id
            tFeedback.feedback = feedback
            db.session.add(tFeedback)
            db.session.commit()

            return {
                'message' : 'Berhasil memberikan feedback!',
                'created_at' : tFeedback.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }, 200
        else:
            return {'message': 'Token tidak valid, silahkan masuk dulu'}, 401    

# API LogOut
   

#running this webservice

application = app.wsgi_app

if __name__ == '__main__':
    # app.run(debug=True, host='0.0.0.0')
    socketio.run(app, debug=True, host='0.0.0.0')