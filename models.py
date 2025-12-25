import datetime
import os
import uuid
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Relationships
    projects = db.relationship('Project', backref='owner', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    folder_path = db.Column(db.String(255), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    is_running = db.Column(db.Boolean, default=False)
    port = db.Column(db.Integer)
    pid = db.Column(db.Integer)
    entry_point = db.Column(db.String(255))
    requirements_file = db.Column(db.Boolean, default=False)

    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships
    files = db.relationship('File', backref='project', lazy='dynamic', cascade='all, delete-orphan')
    folders = db.relationship('Folder', backref='project', lazy='dynamic', cascade='all, delete-orphan')
    commits = db.relationship('Commit', backref='project', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def file_count(self):
        return self.files.count()

    @property
    def last_updated(self):
        return self.updated_at.strftime('%Y-%m-%d %H:%M:%S')

    @property
    def has_requirements_file(self):
        """Check if requirements.txt exists in the project folder"""
        if not self.folder_path:
            return False
        requirements_path = os.path.join(self.folder_path, 'requirements.txt')
        # Always check the file system directly
        exists = os.path.exists(requirements_path) and os.path.isfile(requirements_path)
        # If the file exists but the flag is not set, update it immediately
        if exists and not self.requirements_file:
            self.requirements_file = True
            db.session.commit()
            print(f"Auto-updated requirements_file flag for project {self.id} to True")
        # If the file doesn't exist but the flag is set, update it immediately
        elif not exists and self.requirements_file:
            self.requirements_file = False
            db.session.commit()
            print(f"Auto-updated requirements_file flag for project {self.id} to False")
        # Return the actual file existence
        return exists

    def update_requirements_status(self):
        """Update the requirements_file flag based on file existence"""
        # This will trigger the has_requirements_file property which now auto-updates
        return self.has_requirements_file

    def create_folder(self):
        """Create a unique folder for the project"""
        if not self.folder_path:
            self.folder_path = os.path.join('user_projects', f"{self.user_id}_{uuid.uuid4().hex}")
            if not os.path.exists(self.folder_path):
                os.makedirs(self.folder_path)


class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    path = db.Column(db.String(255), nullable=False)  # Relative path within the project
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Foreign keys
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    parent_folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)

    # Relationships
    files = db.relationship('File', backref='folder', lazy='dynamic', cascade='all, delete-orphan')
    subfolders = db.relationship('Folder', backref=db.backref('parent', remote_side=[id]),
                                lazy='dynamic', cascade='all, delete-orphan')

    @property
    def full_path(self):
        project = Project.query.get(self.project_id)
        return os.path.join(project.folder_path, self.path)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    path = db.Column(db.String(255), nullable=False)  # Relative path within the project
    content = db.Column(db.Text)
    is_binary = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Foreign keys
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)

    # Relationships
    file_versions = db.relationship('FileVersion', backref='file', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def full_path(self):
        project = Project.query.get(self.project_id)
        return os.path.join(project.folder_path, self.path)


class FileVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Foreign keys
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    commit_id = db.Column(db.Integer, db.ForeignKey('commit.id'), nullable=False)


class Commit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Foreign keys
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships
    file_versions = db.relationship('FileVersion', backref='commit', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def user(self):
        return User.query.get(self.user_id)


class AppLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    log_type = db.Column(db.String(50))  # stdout, stderr, system, terminal

    # Foreign keys
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)


class TerminalCommand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    command = db.Column(db.String(255), nullable=False)
    output = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String(50), default='pending')  # pending, completed, failed

    # Foreign keys
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
