from flask import render_template, redirect, request, session, url_for, flash
from werkzeug.utils import secure_filename
from shadow_sec import app, db, bcrypt, ALLOWED_EXTENSIONS
from flask_socketio import emit
from shadow_sec import socketio
import os

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="Member")
    profile_picture = db.Column(db.String(200), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(80), default="Offline")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(200), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    channel_name = db.Column(db.String(80), nullable=True)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    memberships = db.relationship('GroupMembership', cascade="all, delete-orphan", backref='group')
    messages = db.relationship('Message', cascade="all, delete-orphan", backref='group')

class GroupMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)

# Helper function
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route("/", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("main_hub"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session["username"] = username
            session["role"] = user.role
            user.status = "Online"
            db.session.commit()
            return redirect(url_for("main_hub"))

        return "Invalid username or password", 401

    return render_template("login.html")

@app.route("/logout")
def logout():
    if "username" in session:
        user = User.query.filter_by(username=session["username"]).first()
        if user:
            user.status = "Offline"
            db.session.commit()
        session.pop("username", None)
        session.pop("role", None)
    return redirect(url_for("login"))

@app.route("/main_hub", methods=["GET", "POST"])
def main_hub():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        message_content = request.form.get("message")
        file = request.files.get("file")
        file_path = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

        new_message = Message(username=session["username"], content=message_content, file_path=file_path, channel_name="main_hub")
        db.session.add(new_message)
        db.session.commit()

        socketio.emit("new_message", {
            "username": session["username"],
            "message": message_content,
            "file": file_path
        }, to=None)

        return redirect(url_for("main_hub"))

    users = User.query.all()
    messages = Message.query.filter_by(channel_name="main_hub").all()
    return render_template("index.html", users=users, messages=messages)

@app.route("/user/<username>", methods=["GET"], endpoint="view_user_profile")
def view_user_profile(username):
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found", 404

    return render_template("user_profile.html", user=user)

@app.route("/profile", methods=["GET", "POST"], endpoint="edit_user_profile")
def edit_user_profile():
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()

    if request.method == "POST":
        user.bio = request.form.get("bio")
        user.status = request.form.get("status")

        if "profile_picture" in request.files:
            file = request.files["profile_picture"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(filepath)
                user.profile_picture = filepath

        db.session.commit()
        return redirect(url_for("edit_user_profile"))

    return render_template("profile.html", user=user)

@app.route("/message/<username>", methods=["GET", "POST"], endpoint="private_message")
def private_message(username):
    if "username" not in session:
        return redirect(url_for("login"))
    
    sender = User.query.filter_by(username=session["username"]).first()
    recipient = User.query.filter_by(username=username).first()
    
    if not recipient:
        return "User not found", 404
    
    if request.method == "POST":
        message_content = request.form.get("message")
        file = request.files.get("file")
        file_path = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

        new_message = Message(
            username=sender.username,
            content=message_content,
            file_path=file_path,
            channel_name=f"private_{sender.username}_{recipient.username}"
        )
        db.session.add(new_message)
        db.session.commit()

        socketio.emit(
            "private_message",
            {
                "sender": sender.username,
                "recipient": recipient.username,
                "message": message_content,
                "file_path": file_path
            },
            room=recipient.username
        )
    
    # Retrieve messages between the two users
    channel_name = f"private_{sender.username}_{recipient.username}"
    reverse_channel_name = f"private_{recipient.username}_{sender.username}"
    messages = Message.query.filter(
        (Message.channel_name == channel_name) | (Message.channel_name == reverse_channel_name)
    ).all()

    return render_template("private_message.html", recipient=recipient, messages=messages)

@socketio.on("send_private_message")
def handle_send_private_message(data):
    sender = User.query.filter_by(username=data["sender"]).first()
    recipient = User.query.filter_by(username=data["recipient"]).first()

    if not recipient:
        emit("error", {"message": "Recipient not found"}, to=sender.username)
        return

    # Emit the message to the recipient
    emit(
        "receive_private_message",
        {
            "sender": sender.username,
            "message": data["message"]
        },
        room=recipient.username
    )


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.', 'error')
            return redirect(url_for('register'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user and save to the database
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route("/groups", methods=["GET", "POST"])
def groups():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        if session.get("role") not in ["Admin", "Moderator"]:
            flash("You do not have permission to create groups.", "error")
            return redirect(url_for("groups"))

        group_name = request.form.get("name")
        description = request.form.get("description")
        creator = User.query.filter_by(username=session["username"]).first()

        if Group.query.filter_by(name=group_name).first():
            flash("Group name already exists!", "error")
            return redirect(url_for("groups"))

        new_group = Group(name=group_name, description=description, creator_id=creator.id)
        db.session.add(new_group)
        db.session.commit()

        flash("Group created successfully!", "success")
        return redirect(url_for("groups"))

    groups = Group.query.all()
    return render_template("groups.html", groups=groups)

@app.route("/join_group/<int:group_id>", methods=["POST"])
def join_group(group_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()
    group = Group.query.get_or_404(group_id)

    # Check if user is already a member
    if GroupMembership.query.filter_by(user_id=user.id, group_id=group.id).first():
        flash("You are already a member of this group.", "info")
        return redirect(url_for("groups"))

    # Add user to the group
    membership = GroupMembership(user_id=user.id, group_id=group.id)
    db.session.add(membership)
    db.session.commit()

    flash("You have joined the group successfully!", "success")
    return redirect(url_for("group_chat", group_id=group.id))


@app.route("/group/<int:group_id>", methods=["GET", "POST"])
def group_chat(group_id):
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()
    group = Group.query.get_or_404(group_id)

    if not GroupMembership.query.filter_by(user_id=user.id, group_id=group.id).first():
        membership = GroupMembership(user_id=user.id, group_id=group.id)
        db.session.add(membership)
        db.session.commit()
        flash("You have joined the group successfully!", "success")

    if request.method == "POST":
        message_content = request.form.get("message")
        file = request.files.get("file")
        file_path = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

        new_message = Message(
            username=session["username"],
            content=message_content,
            file_path=file_path,
            group_id=group_id
        )
        db.session.add(new_message)
        db.session.commit()

        socketio.emit(
            "new_group_message",
            {"username": session["username"], "message": message_content, "file": file_path},
            to=f"group_{group_id}"
        )

        return redirect(url_for("group_chat", group_id=group_id))

    messages = Message.query.filter_by(group_id=group_id).all()
    return render_template("group_chat.html", group=group, messages=messages)

@app.route("/delete_group/<int:group_id>", methods=["POST"])
def delete_group(group_id):
    if "username" not in session or session.get("role") != "Admin":
        return "Access denied", 403

    group = Group.query.get(group_id)
    if group:
        db.session.delete(group)
        db.session.commit()

    return redirect(url_for("admin_dashboard"))

@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    if "username" not in session or session.get("role") != "Admin":
        return "Access denied", 403

    users = User.query.all()
    groups = Group.query.all()
    return render_template("admin_dashboard.html", users=users, groups=groups)

@app.route("/update_user_role", methods=["POST"])
def update_user_role():
    if "username" not in session or session.get("role") != "Admin":
        return "Access denied", 403

    user_id = request.form.get("user_id")
    new_role = request.form.get("role")

    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    # Update the role
    user.role = new_role
    db.session.commit()

    flash("User role updated successfully!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()

    if request.method == "POST":
        user.bio = request.form.get("bio")
        user.status = request.form.get("status")

        if "profile_picture" in request.files:
            file = request.files["profile_picture"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(filepath)
                user.profile_picture = filepath

        db.session.commit()
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)

@app.route("/user/<username>")
def user_profile(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found", 404

    return render_template("user_profile.html", user=user)

@app.route("/main_hub/<channel_name>", methods=["GET", "POST"])
def chat_channel(channel_name):
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        message_content = request.form.get("message")
        file = request.files.get("file")
        file_path = None

        # Check if the message starts with a command
        if message_content and message_content.startswith("/"):
            if session.get("role") == "Admin":
                command_response = handle_admin_command(message_content, channel_name)
                messages = Message.query.filter_by(channel_name=channel_name).all()
                users = User.query.filter_by(status="Online").all()
                return render_template(
                    f"{channel_name}.html",
                    messages=messages,
                    current_channel=channel_name,
                    users=users,
                    command_response=command_response
                )
            else:
                messages = Message.query.filter_by(channel_name=channel_name).all()
                users = User.query.filter_by(status="Online").all()
                return render_template(
                    f"{channel_name}.html",
                    messages=messages,
                    current_channel=channel_name,
                    users=users,
                    command_response="You do not have permission to use commands."
                )

        # Handle file upload if provided
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(file_path)

        # Save the message with the channel name
        if message_content:
            new_message = Message(
                username=session["username"],
                content=message_content,
                file_path=file_path,
                channel_name=channel_name  # Save the current channel
            )
            db.session.add(new_message)
            db.session.commit()

    # Fetch only the messages for the current channel
    messages = Message.query.filter_by(channel_name=channel_name).all()

    # Fetch all users, filter online users, and pass them to the template
    users = User.query.filter_by(status="Online").all()

    return render_template(
        f"{channel_name}.html",
        messages=messages,
        current_channel=channel_name,
        users=users
    )

@app.route("/get_commands", methods=["GET"])
def get_commands():
    commands = [
        {"command": "/clear", "description": "Clear all messages in the current channel."},
        {"command": "/kick <username>", "description": "Kick a user from the system."},
        {"command": "/mute <username>", "description": "Mute a user in the current channel."},
        {"command": "/unmute <username>", "description": "Unmute a user in the current channel."},
        {"command": "/ban <username>", "description": "Ban a user from the current channel."},
        {"command": "/unban <username>", "description": "Unban a user from the current channel."},
        {"command": "/announce <message>", "description": "Send an announcement in the current channel."},
    ]
    return jsonify(commands)

def handle_admin_command(command, channel_name):
    """
    Handle admin commands like /clear, /kick, /mute, /ban, /unban, /announce, etc.
    """
    if command.startswith("/clear"):
        # Clear all messages in the channel
        Message.query.filter_by(channel_name=channel_name).delete()
        db.session.commit()
        return f"All messages in #{channel_name} have been cleared by admin."
    
    elif command.startswith("/kick"):
        # Kick a user (extract username)
        username = command.split(" ")[1] if len(command.split(" ")) > 1 else None
        if username:
            session.pop(username, None)
            return f"User '{username}' has been kicked out of the system."
        return "Please specify a user to kick. Usage: /kick <username>"

    elif command.startswith("/mute"):
        # Mute a user (extract username)
        username = command.split(" ")[1] if len(command.split(" ")) > 1 else None
        if username:
            # Add user to a muted users table (or a similar mechanism)
            muted_user = MutedUser(username=username, channel_name=channel_name)
            db.session.add(muted_user)
            db.session.commit()
            return f"User '{username}' has been muted in #{channel_name}."
        return "Please specify a user to mute. Usage: /mute <username>"

    elif command.startswith("/unmute"):
        # Unmute a user (extract username)
        username = command.split(" ")[1] if len(command.split(" ")) > 1 else None
        if username:
            MutedUser.query.filter_by(username=username, channel_name=channel_name).delete()
            db.session.commit()
            return f"User '{username}' has been unmuted in #{channel_name}."
        return "Please specify a user to unmute. Usage: /unmute <username>"

    elif command.startswith("/ban"):
        # Ban a user (extract username)
        username = command.split(" ")[1] if len(command.split(" ")) > 1 else None
        if username:
            banned_user = BannedUser(username=username, channel_name=channel_name)
            db.session.add(banned_user)
            db.session.commit()
            return f"User '{username}' has been banned from #{channel_name}."
        return "Please specify a user to ban. Usage: /ban <username>"

    elif command.startswith("/unban"):
        # Unban a user (extract username)
        username = command.split(" ")[1] if len(command.split(" ")) > 1 else None
        if username:
            BannedUser.query.filter_by(username=username, channel_name=channel_name).delete()
            db.session.commit()
            return f"User '{username}' has been unbanned in #{channel_name}."
        return "Please specify a user to unban. Usage: /unban <username>"

    elif command.startswith("/announce"):
        # Announce a message (extract announcement content)
        announcement = " ".join(command.split(" ")[1:])
        if announcement:
            new_message = Message(
                username="System",
                content=f"ANNOUNCEMENT: {announcement}",
                channel_name=channel_name
            )
            db.session.add(new_message)
            db.session.commit()
            return f"Announcement sent: {announcement}"
        return "Please specify an announcement. Usage: /announce <message>"

    else:
        # Unknown command
        return f"Unknown command: {command}. Use /help for a list of valid commands."


