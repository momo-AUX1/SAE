from flask import *
from flask_cors import *
from flask_sqlalchemy import *
from flask_jwt_extended import *
from flask_login import *
import os
from datetime import timedelta, datetime
from werkzeug.security import generate_password_hash, check_password_hash  
import requests

IS_PROD = False
PHOTO_PATH = 'photos/'

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///preprod.db' if not IS_PROD else 'mysql://SAECROSS:ZrKrfEZAEJkv6CWIw8au@127.0.0.1:3306/SAECROSS'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_KEY', open('jwt.key').read())
db = SQLAlchemy(app)
jwt = JWTManager(app)
login_manager = LoginManager()
login_manager.init_app(app)

MAILJET_USERNAME = ""
MAILJET_PASSWORD = ""

# DB Models
class utilisateurs(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    mdp = db.Column(db.String(255), nullable=False)
    nom = db.Column(db.String(255), nullable=False)
    adresse = db.Column(db.String(255), nullable=False)

class signalements(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    categorie = db.Column(db.String(255), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Boolean, default=False, nullable=False)
    id_user = db.Column(db.Integer, db.ForeignKey('utilisateurs.id'), nullable=False)
    photo_path = db.Column(db.String(255), nullable=True)

class PushToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('utilisateurs.id'), nullable=False)
    token = db.Column(db.String(255), nullable=False, unique=True)
    user = db.relationship('utilisateurs', backref=db.backref('push_tokens', lazy=True))

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return "hello world!"

def hash_password(password):
    return generate_password_hash(password)

def check_password(hashed_password, password):
    return check_password_hash(hashed_password, password)

@app.route('/api/register', methods=['POST'])
def register_req():
    data = request.get_json()

    if not data.get('email') or not data.get('mdp') or not data.get('nom') or not data.get('adresse'):
        return jsonify({'message': 'Missing information'}), 400
    
    exists = utilisateurs.query.filter_by(email=data['email']).first()
    if exists:
        return jsonify({'message': 'Email already in use'}), 400
    
    new_user = utilisateurs(
        email=data['email'],
        mdp=hash_password(data['mdp']),  
        nom=data['nom'],
        adresse=data['adresse']
    )

    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login_req():
    data = request.get_json()
    
    if not data.get('email') or not data.get('mdp'):
        return jsonify({'message': 'Missing credentials'}), 400
    
    user = utilisateurs.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401
    
    if check_password(user.mdp, data['mdp']):  
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user_id': user.id
        }), 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

@app.route('/api/submit_signalement', methods=['POST'])
@jwt_required()
def submit_signalement():
    data = request.form.to_dict()
    current_user = get_jwt_identity()
    user = utilisateurs.query.get(current_user)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404

    if not data.get('categorie') or not data.get('message'):
        return jsonify({'message': 'Missing information'}), 400
    
    photo_path = None
    if 'photo' in request.files:
        photo = request.files['photo']
        if photo.filename != '':
            photo_path = os.path.join(PHOTO_PATH, f"{user.id}_{datetime.utcnow().timestamp()}_{photo.filename}")
            photo.save(photo_path)

    new_signalement = signalements(
        categorie=data['categorie'],
        message=data['message'],
        date=datetime.utcnow(),
        id_user=user.id,
        photo_path=photo_path,
        status=False
    )

    db.session.add(new_signalement)
    db.session.commit()
    return jsonify({'message': 'Signalement submitted successfully'}), 201

@app.route('/api/user', methods=['PATCH'])
@jwt_required()
def modify_user():
    current_user_id = get_jwt_identity()
    user = utilisateurs.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'message': 'No data provided'}), 400

    if 'email' in data:
        if utilisateurs.query.filter(utilisateurs.email == data['email'], utilisateurs.id != current_user_id).first():
            return jsonify({'message': 'Email already in use'}), 400
        user.email = data['email']
    
    if 'nom' in data:
        user.nom = data['nom']
    
    if 'adresse' in data:
        user.adresse = data['adresse']
    
    if 'new_password' in data:
        if 'old_password' not in data:
            return jsonify({'message': 'Old password required for password change'}), 400
        
        if not check_password(user.mdp, data['old_password']):
            return jsonify({'message': 'Invalid old password'}), 401
        
        user.mdp = hash_password(data['new_password'])

    db.session.commit()
    return jsonify({'message': 'User updated successfully'}), 200

@app.route('/api/signalement/<int:signalement_id>/status', methods=['PATCH'])
@jwt_required()
def change_signalment_status(signalement_id):
    current_user_id = get_jwt_identity()
    signalement = signalements.query.get(signalement_id)
    
    if not signalement:
        return jsonify({'message': 'Signalement not found'}), 404
    
    if signalement.id_user != int(current_user_id):
        return jsonify({'message': 'Unauthorized to modify this signalement'}), 403

    data = request.get_json()
    if 'status' not in data or not isinstance(data['status'], bool):
        return jsonify({'message': 'Invalid status value'}), 400

    signalement.status = data['status']
    db.session.commit()
    return jsonify({'message': f'Signalment status updated to {data["status"]}'}), 200

@app.route('/api/register_push_token', methods=['POST'])
@jwt_required()
def register_push_token():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'token' not in data or not data['token']:
        return jsonify({'message': 'Token is required'}), 400
    
    existing_token = PushToken.query.filter_by(token=data['token']).first()
    if existing_token:
        if existing_token.user_id != int(current_user_id):
            db.session.delete(existing_token)
        else:
            return jsonify({'message': 'Token already registered for this user'}), 200
    
    new_token = PushToken(
        user_id=current_user_id,
        token=data['token']
    )
    
    db.session.add(new_token)
    db.session.commit()
    return jsonify({'message': 'Push token registered successfully'}), 201

@app.route('/api/send_email', methods=['POST'])
def send_email():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('subject') or not data.get('body'):
        return jsonify({'message': 'Missing email, subject, or body'}), 400
    
    emails = data['email'].split('|') if '|' in data['email'] else [data['email']]
    
    try:
        for email in emails:
            email_body = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{data['subject']}</title>
    <style>
        body {{
            background-color: #f5f9f0;
            color: #2c3e50;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }}
        .header {{
            background-color: #27ae60;
            padding: 20px;
            text-align: center;
        }}
        .header h1 {{
            color: white;
            margin: 0;
            font-size: 24px;
        }}
        .content {{
            padding: 30px;
            line-height: 1.6;
        }}
        .footer {{
            background-color: #f1f8e9;
            padding: 20px;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }}
        .greenda-logo {{
            color: #27ae60;
            font-weight: bold;
            font-size: 18px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Greenda</h1>
        </div>
        
        <div class="content">
            {data['body']}
        </div>
        
        <div class="footer">
            <p>This email was sent from <span class="greenda-logo">Greenda</span></p>
            <p>© {datetime.now().year} Greenda. All rights reserved.</p>
            <p>Contact us at: <a href="mailto:greenda@greenda.com">greenda@greenda.com</a></p>
        </div>
    </div>
</body>
</html>
            """
            
            response = requests.post(
                "https://api.mailjet.com/v3.1/send",
                auth=(MAILJET_USERNAME, MAILJET_PASSWORD),
                json={
                    "Messages": [
                        {
                            "From": {"Email": "greenda@greenda.com", "Name": "Greenda"},
                            "To": [{"Email": email}],
                            "Subject": data['subject'],
                            "HTMLPart": email_body,
                        }
                    ]
                },
            )
            
            if response.status_code != 200:
                app.logger.error(f"Mailjet error: {response.status_code} - {response.text}")
                return jsonify({'message': f'Error sending email to {email}'}), 500
        
        return jsonify({'message': 'Emails sent successfully'}), 200
        
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")
        return jsonify({'message': f'Error: {str(e)}'}), 500

def serialize_signalement(s):
    return {
        'id': s.id,
        'categorie': s.categorie,
        'message': s.message,
        'date': s.date.isoformat(),
        'status': s.status,
        'photo_path': s.photo_path,
        'user_id': s.id_user
    }

@app.route('/api/signalements', methods=['GET'])
@jwt_required()
def get_all_signalements():
    all_signalements = signalements.query.all()
    return jsonify([serialize_signalement(s) for s in all_signalements]), 200

@app.route('/api/signalement/<int:signalement_id>', methods=['GET'])
@jwt_required()
def get_signalement(signalement_id):
    signalement = signalements.query.get(signalement_id)
    if not signalement:
        return jsonify({'message': 'Signalement not found'}), 404
    return jsonify(serialize_signalement(signalement)), 200

@app.route('/api/user/signalements', methods=['GET'])
@jwt_required()
def get_user_signalements():
    current_user_id = get_jwt_identity()
    user_signalements = signalements.query.filter_by(id_user=current_user_id).all()
    return jsonify([serialize_signalement(s) for s in user_signalements]), 200

@app.route('/api/signalement/<int:signalement_id>', methods=['PATCH'])
@jwt_required()
def edit_signalement(signalement_id):
    current_user_id = get_jwt_identity()
    signalement = signalements.query.get(signalement_id)
    
    if not signalement:
        return jsonify({'message': 'Signalement not found'}), 404
    
    if signalement.id_user != int(current_user_id):
        return jsonify({'message': 'Unauthorized to modify this signalement'}), 403

    data = request.get_json()
    updates = {}
    
    if 'categorie' in data:
        updates['categorie'] = data['categorie']
    if 'message' in data:
        updates['message'] = data['message']
    
    if not updates:
        return jsonify({'message': 'No updates provided'}), 400
    
    for key, value in updates.items():
        setattr(signalement, key, value)
    
    db.session.commit()
    return jsonify({'message': 'Signalement updated successfully'}), 200

@app.route('/api/user', methods=['GET'])
@jwt_required()
def get_user_info():
    current_user_id = get_jwt_identity()
    user = utilisateurs.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify({
        'id': user.id,
        'email': user.email,
        'nom': user.nom,
        'adresse': user.adresse
    }), 200

@app.route('/api/user', methods=['DELETE'])
@jwt_required()
def delete_user():
    current_user_id = get_jwt_identity()
    user = utilisateurs.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user_signalements = signalements.query.filter_by(id_user=current_user_id).all()
    for s in user_signalements:
        if s.photo_path and os.path.exists(s.photo_path):
            os.remove(s.photo_path)
        db.session.delete(s)
    
    PushToken.query.filter_by(user_id=current_user_id).delete()
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200

if __name__ == '__main__':
    app.run(debug=not IS_PROD, port=8120)