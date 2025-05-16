# Importing the PIL library
from PIL import Image
from PIL import ImageDraw
from PIL import ImageFont
import hashlib
import os
from flask import Flask, render_template, request, redirect, url_for, g, jsonify, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import time
import datetime
from time import ctime, sleep
import threading
import qrcode
import cv2
from flask_cors import CORS, cross_origin
from datetime import datetime
import pathlib
from MailSent import send_email, getDateTime
import os
import time
import base64
from flask import Flask, request, render_template, session, redirect, url_for
import numpy as np
import firebase_admin
import random
from firebase_admin import credentials, firestore
from PIL import Image
import sqlite3
from sqlite3 import Error
import os
import hashlib
import os
from flask import Flask, render_template, current_app, request, redirect, url_for, g, jsonify, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sqlite3
from sqlite3 import Error
import time
import datetime
from time import ctime, sleep
import threading
import qrcode
import cv2
import hashlib
import os
from flask import Flask, render_template, current_app, request, redirect, url_for, g, jsonify, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sqlite3
from sqlite3 import Error
import time
import datetime
from time import ctime, sleep
import threading
import qrcode
import cv2
from pyzbar.pyzbar import decode
from flask_cors import CORS, cross_origin
import json
import requests
from flask_cors import CORS, cross_origin
cred = credentials.Certificate("key.json")
firebase_admin.initialize_app(cred)
app = Flask(__name__)
app.secret_key = "OnlineBlockChainCertificationValidatr@123"
UPLOAD_FOLDER = 'static/uploads/'
#QRCODE_UPLOAD_FOLDER = 'static/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#app.config['QRCODE_UPLOAD_FOLDER'] = QRCODE_UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['CORS_HEADERS'] = 'Content-Type'
ALLOWED_EXTENSIONS = set(['.png', '.jpg', '.jpeg', '.gif'])


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key.pem", "wb") as f:
        f.write(pem)


def save_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(pem)


def load_private_key():
    if os.path.isfile("private_key.pem"):
        with open("private_key.pem", "rb") as f:
            pem = f.read()
            return serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    else:
        return None


def load_public_key():
    if os.path.isfile("public_key.pem"):
        with open("public_key.pem", "rb") as f:
            pem = f.read()
            return serialization.load_pem_public_key(pem, backend=default_backend())
    else:
        return None


private_key = load_private_key()
public_key = load_public_key()
if private_key is None or public_key is None:
    private_key, public_key = generate_key_pair()
    save_private_key(private_key)
    save_public_key(public_key)

@app.before_request
def before_request():
    g.private_key = private_key
    g.public_key = public_key

# Function to generate a QR code
def generate_qr_code(data, output_file):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.save(output_file)
# Function to read a QR code from an image
def read_qr_code(image_path):
    # Load the image
    img = cv2.imread(image_path)

    # Create a QR code detector
    detector = cv2.QRCodeDetector()

    # Detect and decode the QR code
    retval, decoded_info, points, straight_qrcode = detector.detectAndDecodeMulti(
        img)
    print("Ret Value : ", retval)
    print("Decoded Info : ", decoded_info)
    if retval:
        return decoded_info
    else:
        return None


def read_qr_code1(image_path):
    # Load the image containing the QR code
    image = cv2.imread(image_path)

    # Decode the QR code
    decoded_objects = decode(image)

    # Check if any QR code was found in the image
    if decoded_objects:
        for obj in decoded_objects:
            qr_data = obj.data.decode('utf-8')
            qr_type = obj.type
            return qr_data
    else:
        return None

class Block:
    def __init__(self, timestamp, data, previous_hash):
        self.timestamp = timestamp
        self.data = str(data)
        self.previous_hash = previous_hash
        self.current_hash = self.hash_block()
        self.encrypted_data = None
        self.decrypted_data = None

    def encrypt_data(self, public_key):
        data_bytes = self.data.encode()
        encrypted_data = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.encrypted_data = encrypted_data.hex()

    def decrypt_data(self, private_key):
        try:
            encrypted_data = bytes.fromhex(self.encrypted_data)
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.decrypted_data = decrypted_data.decode()
        except Exception as e:
            print(e)

    def hash_block(self):
        input_string = f"{self.timestamp}{self.data}{self.previous_hash}"
        input_bytes = input_string.encode()
        hash_bytes = hashlib.sha256(input_bytes)
        hash_hex = hash_bytes.hexdigest()
        return hash_hex

"""
class Blockchain:
    counter = 0
    def __init__(self):
        pass
        #self.chain = self.load_blocks_from_db()

    def add_block(self, data, public_key):
        Blockchain.counter = round(time.time())
        timestamp = datetime.datetime.now(datetime.timezone(
            datetime.timedelta(hours=5, minutes=30))).strftime("%a %b %d %H:%M:%S %Y")
        previous_hash = self.chain[-1].current_hash if self.chain else ""
        new_block = Block(timestamp, data, previous_hash)
        new_block.encrypt_data(public_key)
        self.chain.append(new_block)
        self.save_to_db(new_block)
        self.return_the_hash(new_block)
        self.create_qr_code(new_block)

    def save_to_db(self, block):        
        id=str(Blockchain.counter)
        json = {'id': id,
                        'TimeStamp': block.timestamp, 'EncryptedData': block.encrypted_data,
                        'PreviousHash': block.previous_hash, 
                        'CurrentHash': block.current_hash}
        print("Json : ",json)
        db = firestore.client()
        newdb_ref = db.collection('newreport')
        newdb_ref.document(id).set(json)

    def return_the_hash(self, block):
        file_path = "hash.txt"
        text_to_add = block.encrypted_data
        try:
            with open(file_path, "a") as file:
                file.writelines(text_to_add + "\n")
        except FileNotFoundError:
            with open(file_path, "w") as file:
                file.writelines(text_to_add + "\n")

    def create_qr_code(self, block):
        qr_code_filename="qr_code"+str(Blockchain.counter)+".png"
        #file_path_qr = f"static/qr_code_{Blockchain.counter}.png"
        file_path_qr = os.path.join(app.config['UPLOAD_FOLDER'],qr_code_filename)
        data_to_be_encoded = block.encrypted_data
        generate_qr_code(data_to_be_encoded, file_path_qr)

blockchain = Blockchain()
"""
def create_connection():
    conn = None
    try:
        if not os.path.exists("logs.db"):
            conn = sqlite3.connect('logs.db')
        else:
            conn = sqlite3.connect('logs.db')
        return conn
    except Error as e:
        print(e)
    return conn

class Blockchain:
    counter = 0
    def __init__(self):
        self.chain = self.load_blocks_from_db()
    def load_blocks_from_db(self):
        conn = create_connection()
        with conn:
            c = conn.cursor()
            try:
                c.execute("SELECT * FROM blocks")
                rows = c.fetchall()
                blocks = []
                for row in rows:
                    timestamp, encrypted_data, previous_hash, current_hash = row
                    new_block = Block(timestamp, "", previous_hash)
                    new_block.encrypted_data = encrypted_data
                    new_block.current_hash = current_hash
                    blocks.append(new_block)
                return blocks
            except sqlite3.OperationalError:
                return []

    def add_block(self, data, public_key):
        #Blockchain.counter += 1
        Blockchain.counter = round(time.time())
        timestamp = datetime.datetime.now(datetime.timezone(
            datetime.timedelta(hours=5, minutes=30))).strftime("%a %b %d %H:%M:%S %Y")
        previous_hash = self.chain[-1].current_hash if self.chain else ""
        new_block = Block(timestamp, data, previous_hash)
        new_block.encrypt_data(public_key)
        self.chain.append(new_block)
        self.save_to_db(new_block)
        self.return_the_hash(new_block)
        self.create_qr_code(new_block)

    def save_to_db(self, block):
        conn = create_connection()
        with conn:
            create_table(conn)
            c = conn.cursor()
            c.execute("INSERT INTO blocks (timestamp, encrypted_data, previous_hash, current_hash) VALUES (?, ?, ?, ?)",
                      (block.timestamp, block.encrypted_data, block.previous_hash, block.current_hash))
            conn.commit()

    def return_the_hash(self, block):
        file_path = "hash.txt"
        text_to_add = block.encrypted_data
        try:
            with open(file_path, "a") as file:
                file.writelines(text_to_add + "\n")
        except FileNotFoundError:
            with open(file_path, "w") as file:
                file.writelines(text_to_add + "\n")

    def create_qr_code(self, block):
        file_path_qr = f"static/qr_code_{Blockchain.counter}.png"
        data_to_be_encoded = block.encrypted_data
        generate_qr_code(data_to_be_encoded, file_path_qr)


def create_table(conn):
    try:
        c = conn.cursor()
        create_table_sql = '''
            CREATE TABLE IF NOT EXISTS blocks
            ("timestamp" TEXT PRIMARY KEY, encrypted_data TEXT, previous_hash TEXT, current_hash TEXT)
        '''
        c.execute(create_table_sql)
    except Error as e:
        print(e)

blockchain = Blockchain()


@app.route('/adminverifycertificate', methods=['POST','GET'])
def adminverifycertificate():
    try:
        db = firestore.client()
        newdata_ref = db.collection('newreport')
        newdata = newdata_ref.get()
        data=[]
        for doc in newdata:
            if(doc.to_dict()['Verified']=='No'):
                data.append(doc.to_dict())
        print("Users Data " , data)
        return render_template("adminverifycertificate.html", data=data)
    except Exception as e:
        return str(e)

@app.route('/adminverifycertificate1', methods=['GET', 'POST'])
def adminverifycertificate1():
    try:
        id=request.args['id']
        db = firestore.client()
        data = db.collection('newreport').document(id).get().to_dict()
        print("User Data ", data)
        return render_template("adminverifycertificate1.html", data=data)
    except Exception as e:
        return str(e)

#@cross_origin(origin='*', headers=['Content-Type', 'Authorization'])
@app.route('/adminverifycertificate2', methods=['GET', 'POST'])
def adminverifycertificate2():
    if request.method == 'POST':        
        data = {
            "sid": request.form['sid'],
            #"email": request.form['email'],
            #"phnumber": request.form['phnumber'],
            "name": request.form['name'],
            "courseid": request.form['courseId'],
            "coursename": request.form['courseName'],
            "instname": request.form['instituteName'],
            "startdate": request.form['startDate'],
            "enddate": request.form['endDate']
        }
        # Extract QR code content from uploaded image (you'll need a QR code library)
        file = request.files['file']
        # Set the directory path for storing the uploaded files
        #upload_directory = './static/uploads'
        # Save the file to the specified directory
        filename = "Uploaded"+str(round(time.time()))+".png"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        # Optionally, you can also store the filepath in a variable for further processing or database storage
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        time.sleep(3)
        print("File Path : ", filepath)
        encrypted_data = read_qr_code1(filepath)
        print("Encrypted Code : ", encrypted_data)
        flag,filename=False,None
        reportid=None
        if(encrypted_data):
            try:
                db = firestore.client()
                newdata_ref = db.collection('newreport')
                newdata = newdata_ref.get()                
                for doc in newdata:
                    temp = doc.to_dict()                    
                    print(data['sid'], " ", temp['StudentId'])
                    if(encrypted_data==temp['EncryptedData'] and
                       data['sid']==temp['StudentId']):
                        flag=True
                        filename=temp['Certificate']
                        reportid=str(temp['id'])
                        break                                   
            except Exception as e:
                return str(e)            
        else:
            msg="Certificate Verification Failed"
        if(flag):
            db = firestore.client()        
            newdb_ref = db.collection('newreport').document(reportid)
            newdb_ref.update({u'Verified': 'Yes'})
            newdb_ref.update({u'CertificateStatus': 'Success'})

            img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            # Save the edited image
            signatureimg_path=os.path.join(app.config['UPLOAD_FOLDER'],"signature.png")
            print(signatureimg_path)
            signatureimg = Image.open(signatureimg_path)

            # Define the position to paste the foreground image
            position = (250, 1200)  # Coordinates (x, y)

            signatureimg = signatureimg.resize((150, 100))  # Adjust size as needed

            # Ensure the foreground image has an alpha channel (transparency)
            #qr_img = qr_img.convert("RGBA")

            # Paste the foreground image onto the background
            img.paste(signatureimg, position, signatureimg)
            #img.show()

            img.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            msg="Certificate Verification Success"
        else:
            msg="Certificate Verification Failed"
        
        print("Msg : ", msg)        
    db = firestore.client()
    newdata_ref = db.collection('newreport')
    newdata = newdata_ref.get()
    data=[]
    for doc in newdata:
        if(doc.to_dict()['Verified']=='No'):
            data.append(doc.to_dict())
    print("Users Data " , data)
    return render_template("adminverifycertificate.html", data=data, msg=msg)

def save_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key.pem", "wb") as f:
        f.write(pem)


def save_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pem", "wb") as f:
        f.write(pem)

def load_private_key():
    if os.path.isfile("private_key.pem"):
        with open("private_key.pem", "rb") as f:
            pem = f.read()
            return serialization.load_pem_private_key(pem, password=None, backend=default_backend())
    else:
        return None

def load_public_key():
    if os.path.isfile("public_key.pem"):
        with open("public_key.pem", "rb") as f:
            pem = f.read()
            return serialization.load_pem_public_key(pem, backend=default_backend())
    else:
        return None

private_key = load_private_key()
public_key = load_public_key()
if private_key is None or public_key is None:
    private_key, public_key = generate_key_pair()
    save_private_key(private_key)
    save_public_key(public_key)

@app.before_request
def before_request():
    g.private_key = private_key
    g.public_key = public_key

class Block:
    def __init__(self, timestamp, data, previous_hash):
        self.timestamp = timestamp
        self.data = str(data)
        self.previous_hash = previous_hash
        self.current_hash = self.hash_block()
        self.encrypted_data = None
        self.decrypted_data = None

    def encrypt_data(self, public_key):
        data_bytes = self.data.encode()
        encrypted_data = public_key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.encrypted_data = encrypted_data.hex()

    def decrypt_data(self, private_key):
        try:
            encrypted_data = bytes.fromhex(self.encrypted_data)
            decrypted_data = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.decrypted_data = decrypted_data.decode()
        except Exception as e:
            print(e)

    def hash_block(self):
        input_string = f"{self.timestamp}{self.data}{self.previous_hash}"
        input_bytes = input_string.encode()
        hash_bytes = hashlib.sha256(input_bytes)
        hash_hex = hash_bytes.hexdigest()
        return hash_hex

@app.route("/")
def index():
    private_key = g.private_key
    blocks = []
    for block in blockchain.chain:
        if block.timestamp == 0:
            continue
        if block.decrypted_data is None:
            block.decrypt_data(private_key)
        block_dict = {
            "timestamp": block.timestamp,
            "data": block.decrypted_data,
            "previous_hash": block.previous_hash,
            "current_hash": block.current_hash
        }
        blocks.append(block_dict)
    # return render_template("index.html", blocks=blocks)
    return render_template("index.html")


@app.route("/add_block", methods=["POST"])
# @cross_origin()
@cross_origin(origin='*', headers=['Content-Type', 'Authorization'])
def add_block():
    if request.method == 'POST':
        # Retrieve the form data submitted by the user        
        data = {
            "sid": request.form['sid'],
            "name": request.form['name'],
            "email": request.form['email'],
            "phnumber": request.form['phnumber'],
            "coursename": request.form['coursename'],
            "courseid": request.form['courseid'],
            "instname": request.form['instname'],
            "startdate": request.form['startdate'],
            "enddate": request.form['enddate']
        }
        public_key = g.public_key
        blockchain.add_block(str(json.dumps(data)), public_key)
        generated_qr_code = f"qr_code{blockchain.counter}.png"
        response_data = {
            "qr_code": generated_qr_code
        }
        print("Response_data = ", response_data)

        # Open an Image
        certificate_path=os.path.join(app.config['UPLOAD_FOLDER'],"certificate_template.png")
        img = Image.open(certificate_path)
 
        # Call draw Method to add 2D graphics in an image
        I1 = ImageDraw.Draw(img)
 
        # Custom font style and font size
        myFont = ImageFont.truetype("arial.ttf", 65)
 
        # Add Text to an image
        I1.text((190, 420), data["name"], font=myFont, fill =(255, 255, 255))

        I1.text((210, 620), data["coursename"], font=myFont, fill =(255, 255, 255))

        I1.text((550, 674), data["courseid"], font=myFont, fill =(255, 255, 255))

        I1.text((210, 800), data["instname"], font=myFont, fill =(255, 255, 255))

        myFont = ImageFont.truetype("arial.ttf", 60)

        I1.text((400, 880), data["startdate"], font=myFont, fill =(255, 255, 255))

        I1.text((850, 880), data["enddate"], font=myFont, fill =(255, 255, 255))
 
        # Display edited image
        #img.show()
        filename=f"Certificate{blockchain.counter}.png"
        img.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
        img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'],filename))
        # Save the edited image
        qrcode_path=os.path.join(app.config['UPLOAD_FOLDER'],generated_qr_code)
        print(qrcode_path)
        qr_img = Image.open(qrcode_path)

        # Define the position to paste the foreground image
        position = (1600, 980)  # Coordinates (x, y)

        qr_img = qr_img.resize((300, 300))  # Adjust size as needed

        # Ensure the foreground image has an alpha channel (transparency)
        #qr_img = qr_img.convert("RGBA")

        # Paste the foreground image onto the background
        img.paste(qr_img, position, qr_img)

        img.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))

        db = firestore.client()
        id=str(blockchain.counter)
        newdb_ref = db.collection('newreport').document(id)
        newdb_ref.update({u'StudentId': data['sid']}) 
        newdb_ref.update({u'StudentName': data['name']})
        newdb_ref.update({u'CourseName': data['coursename']})
        newdb_ref.update({u'CourseId': data['courseid']})
        newdb_ref.update({u'StartDate': data['startdate']})
        newdb_ref.update({u'EndDate': data['enddate']})
        newdb_ref.update({u'InstituteName': data['instname']})
        newdb_ref.update({u'QRCode': generated_qr_code})
        newdb_ref.update({u'Certificate': filename})
        newdb_ref.update({u'Verified': "No"})
        newdb_ref.update({u'CertificateStatus': "Not Verified"})
        
    return redirect("admincreatecertificate")

@app.route('/adminmainpage')
def adminmainpage():
    try:
        return render_template("adminmainpage.html")
    except Exception as e:
        return str(e)

@app.route('/usermainpage')
def usermainpage():
    try:
        return render_template("usermainpage.html")
    except Exception as e:
        return str(e)

@app.route('/index')
def indexpage():
    try:
        return render_template("index.html")
    except Exception as e:
        return str(e)

@app.route('/logout')
def logoutpage():
    try:
        session['id']=None
        return render_template("index.html")
    except Exception as e:
        return str(e)

@app.route('/about')
def aboutpage():
    try:
        return render_template("about.html")
    except Exception as e:
        return str(e)

@app.route('/services')
def servicespage():
    try:
        return render_template("services.html")
    except Exception as e:
        return str(e)

@app.route('/gallery')
def gallerypage():
    try:
        return render_template("gallery.html")
    except Exception as e:
        return str(e)

@app.route('/adminlogin', methods=['GET','POST'])
def adminloginpage():
    msg=""
    if request.method == 'POST':
        uname = request.form['uname'].lower()
        pwd = request.form['pwd'].lower()
        print("Uname : ", uname, " Pwd : ", pwd)
        if uname == "admin" and pwd == "admin":
            return redirect(url_for("adminmainpage"))
        else:
            msg = "UserName/Password is Invalid"
    return render_template("adminlogin.html", msg=msg)

@app.route('/newuser', methods=['POST','GET'])
def newuser():
    try:
        #print("Add New User page")
        msg=""        
        if request.method == 'POST':
            fname = request.form['fname']
            lname = request.form['lname']
            uname = request.form['uname']
            pwd = request.form['pwd']
            email = request.form['email']
            phnum = request.form['phnum']
            address = request.form['address']            
            id = str(round(time.time()))
            print("User Name : ", uname)
            db = firestore.client()
            dbref = db.collection('newuser')
            userdata = dbref.get()
            data = []
            for doc in userdata:
                data.append(doc.to_dict())
            flag = True
            if uname == "admin":
                flag=False
            for temp in data:
                if uname == temp['UserName'] or email == temp['EmailId'] or phnum == temp['PhoneNumber']:
                    flag = False
                    break
            if(flag):
                json = {'id': id,
                        'FirstName': fname, 'LastName': lname,
                        'UserName': uname, 'Password': pwd,
                        'EmailId': email, 'PhoneNumber': phnum,
                        'Address': address}
                print("Json : ",json)
                db = firestore.client()
                newuser_ref = db.collection('newuser')
                id = json['id']
                newuser_ref.document(id).set(json)
                msg = "New User Added Success"
            else:
                msg = "Duplicate UserName/EmailId/PhoneNum"
        return render_template("newuser.html", msg=msg)
    except Exception as e:
        return str(e)

@app.route('/userlogin', methods=['GET','POST'])
def userloginpage():
    msg=""
    if request.method == 'POST':
        uname = request.form['uname']
        pwd = request.form['pwd']
        db = firestore.client()
        dbref = db.collection('newuser')
        userdata = dbref.get()
        data = []
        for doc in userdata:
            print(doc.to_dict())
            print(f'{doc.id} => {doc.to_dict()}')
            data.append(doc.to_dict())
        flag = False
        for temp in data:
            #print("Pwd : ", temp['Password'])
            #decode = base64.b64decode(temp['Password']).decode("utf-8")
            if uname == temp['UserName'] and pwd == temp['Password']:
                session['userid'] = temp['id']
                session['username'] = temp['FirstName'] + " " + temp['LastName']
                flag = True
                break
        if (flag):
            return render_template("usermainpage.html")
        else:
            msg = "UserName/Password is Invalid"
    return render_template("userlogin.html", msg=msg)

@app.route('/userviewprofile')
def userviewprofile():
    try:
        id=session['userid']
        db = firestore.client()
        data = db.collection('newuser').document(id).get().to_dict()
        print("User Data ", data)
        return render_template("userviewprofile.html", data=data)
    except Exception as e:
        return str(e)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/contact', methods=['POST','GET'])
def contactpage():
    try:
        msg=""
        if request.method == 'POST':
            cname = str(request.form['cname'])
            subject = request.form['subject']
            message = request.form['message']
            phnum = request.form['phnum']
            email = request.form['email']
            id = str(random.randint(1000, 9999))
            json = {'id': id,
                    'ContactName': cname, 'Subject': subject,
                    'Message': message,'PhoneNumber': phnum,
                    'EmailId': email}
            db = firestore.client()
            newdb_ref = db.collection('newcontact')
            id = json['id']
            newdb_ref.document(id).set(json)
            body = "Thank you for contacting us, " + str(cname) + " We will keep in touch with in 24 Hrs"
            receipients = [email]
            send_email(subject,body,recipients=receipients)
            msg = "New Contact Added Success"
        return render_template("contact.html", msg=msg)
    except Exception as e:
        return str(e)

@app.route('/adminviewusers', methods=['POST','GET'])
def adminviewusers():
    try:
        db = firestore.client()
        newdata_ref = db.collection('newuser')
        newdata = newdata_ref.get()
        data=[]
        for doc in newdata:
            data.append(doc.to_dict())
        print("Users Data " , data)
        return render_template("adminviewusers.html", data=data)
    except Exception as e:
        return str(e)

@app.route('/admincreatecertificate', methods=['POST','GET'])
def admincreatecertificate():
    try:
        db = firestore.client()
        newdata_ref = db.collection('newuser')
        newdata = newdata_ref.get()
        data=[]
        for doc in newdata:
            data.append(doc.to_dict())
        print("Users Data " , data)
        return render_template("admincreatecertificate.html", data=data)
    except Exception as e:
        return str(e)

@app.route('/admincreatecertificate1')
def admincreatecertificate1():
    try:
        id=request.args['id']
        db = firestore.client()
        data = db.collection('newuser').document(id).get().to_dict()
        print("User Data ", data)
        return render_template("admincreatecertificate1.html", data=data)
    except Exception as e:
        return str(e)

@app.route('/admincreatecertificate2')
def admincreatecertificate2():
    try:
        id=request.args['id']
        db = firestore.client()
        data = db.collection('newuser').document(id).get().to_dict()
        print("User Data ", data)
        return render_template("admincreatecertificate1.html", data=data)
    except Exception as e:
        return str(e)

@app.route('/adminviewcontacts', methods=['POST','GET'])
def adminviewcontacts():
    try:
        db = firestore.client()
        newdata_ref = db.collection('newcontact')
        newdata = newdata_ref.get()
        data=[]
        for doc in newdata:
            data.append(doc.to_dict())
        print("Contact Data " , data)
        return render_template("adminviewcontacts.html", data=data)
    except Exception as e:
        return str(e)

@app.route('/adminviewreports', methods=['POST','GET'])
def adminviewreports():
    try:
        db = firestore.client()
        newdata_ref = db.collection('newreport')
        newdata = newdata_ref.get()
        data=[]
        for doc in newdata:
            temp = doc.to_dict()
            data.append(temp)        
        print("Report Data " , data)
        return render_template("adminviewreports.html", data=data)
    except Exception as e:
        return str(e)

@app.route('/userviewreports', methods=['POST','GET'])
def userviewreports():
    try:
        db = firestore.client()
        newdata_ref = db.collection('newreport')
        newdata = newdata_ref.get()
        data=[]
        userid = session['userid']
        for doc in newdata:
            temp = doc.to_dict()
            if(temp['StudentId']==str(userid)):
                data.append(temp)
        print("Report Data " , data)
        return render_template("userviewreports.html", data=data)
    except Exception as e:
        return str(e)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    app.debug = True
    app.run()