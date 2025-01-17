from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import mysql.connector
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
from io import BytesIO
from PIL import Image
import os
from werkzeug.utils import secure_filename
from skimage.metrics import structural_similarity as ssim
import cv2


from shape_generator import shape_generator
from generate_room_split import generate_room_split_image


app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = './uploads'
app.config["TEST_IMAGES_FOLDER"] = "test_images"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.config['JWT_SECRET_KEY'] = 'jwt-secrty-key'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']  # Read token from cookies
app.config['JWT_COOKIE_NAME'] = 'access_token_cookie'
app.config['JWT_COOKIE_SECURE'] = False  # Use True for HTTPS
app.config['JWT_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable CSRF for testing


CORS(app, supports_credentials=True)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Database connection
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'apexa_db'
}

def db_connection():
    conn = mysql.connector.connect(**db_config)
    return conn

def log_activity(email, activity):
    conn = db_connection()
    cursor = conn.cursor()
    sql = "INSERT INTO user_activities (email, activity) VALUES (%s, %s)"
    cursor.execute(sql, (email, activity))
    conn.commit()
    cursor.close()
    conn.close()

@app.route('/search', methods=['GET'])
@jwt_required()  
def search():
    query = request.args.get('query')
    
    if not query:
        return jsonify({"Error": "Search query is required"}), 400
    
    conn = db_connection()
    cursor = conn.cursor(dictionary=True)
    
    sql = "SELECT username, email FROM users WHERE username LIKE %s OR email LIKE %s"
    cursor.execute(sql, (f"%{query}%", f"%{query}%"))
    results = cursor.fetchall()
    
    cursor.close()
    conn.close()

    return jsonify({"Status": "Success", "results": results})

@app.route('/adminpage', methods=['GET'])
@jwt_required()
def admin_page():
    current_user = get_jwt_identity()
    return jsonify({'Status': 'Success', 'email': current_user})

@app.route('/user-details', methods=['GET'])
@jwt_required()
def get_user_details():
    conn = db_connection()
    cursor = conn.cursor(dictionary=True)
    sql = "SELECT username, email FROM users WHERE role = 'user'"
    cursor.execute(sql)
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({'Status': 'Success', 'users': users})

@app.route('/deleteuser', methods=['DELETE'])
@jwt_required()
def delete_user():
    email = request.json.get('email')
    conn = db_connection()
    cursor = conn.cursor()
    sql = "DELETE FROM users WHERE email = %s"
    cursor.execute(sql, (email,))
    conn.commit()
    rows_affected = cursor.rowcount
    cursor.close()
    conn.close()
    if rows_affected == 0:
        return jsonify({'Error': 'No user found with this email'})
    log_activity(get_jwt_identity(), f"Deleted user with email {email}")
    return jsonify({'Status': 'Success', 'Message': 'User deleted successfully'})

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    email = data['email']
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    if cursor.fetchone():
        return jsonify({'Error': 'Email already exists'})
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    sql = "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, 'user')"
    cursor.execute(sql, (data['username'], email, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({'Status': 'Success'})

@app.route('/login', methods=['POST'])
def login_user(): 
    data = request.json
    email = data['email']
    conn = db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if not user or not bcrypt.check_password_hash(user['password'], data['password']):
        return jsonify({'Error': 'Invalid email or password'})
    token = create_access_token(identity=user['email'], expires_delta=False)
    log_activity(user['email'], 'User logged in')
    response = make_response({'Status': 'Success', 'role': user['role'],'email':user['email']})
    response.set_cookie('access_token_cookie', token, httponly=True)
    return response

@app.route('/logout', methods=['GET'])
@jwt_required()
def logout_user():
    email = get_jwt_identity()
    log_activity(email, 'User logged out')
    response = make_response({'Status': 'Success'})
    response.delete_cookie('access_token_cookie')
    return response

@app.route('/forgotpassword', methods=['POST'])
def forgot_password():
    data = request.json
    email = data['email']
    conn = db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if not user:
        return jsonify({'Error': 'No email existed'})
    token = create_access_token(identity=email, expires_delta=False)
    reset_url = f"http://localhost:3000/resetpassword/{token}"
    msg = MIMEMultipart()
    msg['From'] = 'teamapexa2024@gmail.com'
    msg['To'] = email
    msg['Subject'] = 'Password Reset'
    msg.attach(MIMEText(f'Click <a href="{reset_url}">here</a> to reset your password.', 'html'))
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login('teamapexa2024@gmail.com', 'glsd dxny pwjo kqoq')
            smtp.sendmail('teamapexa2024@gmail.com', email, msg.as_string())
        log_activity(email, 'Password reset email sent')
        return jsonify({'Status': 'Success', 'Message': 'Email sent'})
    except Exception as e:
        return jsonify({'Error': f'Error sending email: {str(e)}'})

@app.route('/resetpassword/<token>', methods=['POST'])
def reset_password(token):
    data = request.json
    password = data['password']
    try:
        email = get_jwt_identity()
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        conn = db_connection()
        cursor = conn.cursor()
        sql = "UPDATE users SET password = %s WHERE email = %s"
        cursor.execute(sql, (hashed_password, email))
        conn.commit()
        cursor.close()
        conn.close()
        log_activity(email, 'Password reset')
        return jsonify({'Status': 'Success', 'Message': 'Password updated successfully'})
    except Exception as e:
        return jsonify({'Error': f'Invalid or expired token: {str(e)}'})

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_image():
    data = request.json
    file_data = data['fileData']
    conn = db_connection()
    cursor = conn.cursor()
    sql = "INSERT INTO user_input_image (image, email) VALUES (%s, %s)"
    cursor.execute(sql, (file_data, get_jwt_identity()))
    conn.commit()
    cursor.close()
    conn.close()
    log_activity(get_jwt_identity(), 'Uploaded an image')
    return jsonify({'Status': 'Success', 'Message': 'File uploaded successfully'})

@app.route('/get-all-user-inputs', methods=['GET'])
@jwt_required()
def get_user_images():
    conn = db_connection()
    cursor = conn.cursor(dictionary=True)
    sql = "SELECT * FROM user_input WHERE email = %s"
    cursor.execute(sql, (get_jwt_identity(),))
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(data)

@app.route('/api/images', methods=['GET'])
def get_images():
    conn = db_connection()
    cursor = conn.cursor(dictionary=True)
    sql = "SELECT * FROM images LIMIT 3"
    cursor.execute(sql)
    images = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(images)


def fix_base64_padding(base64_string):
    """Fix missing padding in base64 encoded string."""
    missing_padding = len(base64_string) % 4
    if missing_padding:
        base64_string += "=" * (4 - missing_padding)
    return base64_string


@app.route("/upload-image", methods=["POST"])
@jwt_required()  
def upload_input_image():
    data = request.json.get("imageData")
    email = get_jwt_identity()


    if not data:
        return jsonify({"error": "No image data provided"}), 400
    try:
        
        data = fix_base64_padding(data)
        image_data = base64.b64decode(data)
        image = Image.open(BytesIO(image_data))
        
        if not os.path.exists(app.config["UPLOAD_FOLDER"]):
            os.makedirs(app.config["UPLOAD_FOLDER"])
        
        filename = "upload_image.png"  
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        image.save(image_path)


        shape_generated_image_path = shape_generator(image_path)
        generated_room_split_image_path = generate_room_split_image()


        generated_image = cv2.imread(generated_room_split_image_path)
        _, encoded_output = cv2.imencode('.png', generated_image)
        generated_image_blob = encoded_output.tobytes()

        conn = db_connection()
        cursor = conn.cursor(dictionary=True)
        insert_query = "INSERT INTO user_input_image (email, image) VALUES (%s, %s)"
        cursor.execute(insert_query, (email, generated_image_blob))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
                    "Status": "Image uploaded successfully",
                    "uploadedImageUrl": f"/{image_path}",
                    "generated_path": f"/{generated_room_split_image_path}",
                    "generateImagePath": shape_generated_image_path
                }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route("/get-all-images", methods=["GET"])
@jwt_required()
def get_all_user_input_images():
    try:
        conn = db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT id, email, image FROM user_input_image")
        images = cursor.fetchall()

        image_list = []
        for image in images:
            base64_image = base64.b64encode(image['image']).decode("utf-8")
            image_list.append({
                "id": image['id'],
                "email": image['email'],
                "image_data": base64_image
            })

        return jsonify({"status": "success", "images": image_list}), 200

    except Exception as e:
        return jsonify({"error": f"Error fetching images: {str(e)}"}), 500

@app.route('/user-inputs', methods=['POST'])
@jwt_required()
def add_user_inputs():
    data = request.json
    email = get_jwt_identity()  
    number_of_room = data.get("number_of_room")
    land_width = data.get("land_width")
    land_length = data.get("land_length")
    floor_angle = data.get("floor_angle")

    if not all([number_of_room, land_width, land_length, floor_angle, email]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        conn = db_connection()
        cursor = conn.cursor()
        sql = """INSERT INTO user_input (number_of_room, land_width, land_length, floor_angle, email) 
                 VALUES (%s, %s, %s, %s, %s)"""
        cursor.execute(sql, (number_of_room, land_width, land_length, floor_angle, email))
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "User added successfully"}), 201
    except Exception as e:
        return jsonify({"error": "Failed to add user", "details": str(e)}), 500


if __name__ == '__main__':
    app.run(port=8081, debug=True)
