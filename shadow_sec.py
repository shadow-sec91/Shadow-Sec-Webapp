import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from flask_migrate import Migrate

app = Flask(__name__, static_url_path='/static', static_folder='static')


# Initialize Flask app
app = Flask(__name__)
app.secret_key = "your_secret_key_here"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "uploads"

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)

# Allowed file extensions
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "docx", "txt"}

# Ensure the upload folder exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Import routes after initializing app
from shadow_sec_routes import *

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Create a default admin user if it doesn't exist
        if not User.query.filter_by(username="Shadow-Sec").first():
            hashed_password = bcrypt.generate_password_hash("Unknown18!").decode("utf-8")
            admin_user = User(username="Shadow-Sec", password=hashed_password, role="Admin")
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created: username='Shadow-Sec', password='Unknown18!'")
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
