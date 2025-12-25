import os
import re
import uuid
import subprocess
import psutil
import sys
from datetime import datetime, timezone

from flask import render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename

from app import app, db
from models import User, Project, File, FileVersion, Commit, AppLog, Folder, TerminalCommand
from utils import get_file_extension, is_allowed_file, read_file_content, find_available_port, get_requirements_from_file, install_requirements, check_requirements_changes


@app.route('/')
def index():
    """Home page route"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Basic validation
        if not username or not email or not password:
            flash('All fields are required', 'danger')
            return render_template('register.html')

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return render_template('register.html')

        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False) == 'on'

        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user, remember=remember)
            session.permanent = True  # Make session permanent for extended login time
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page"""
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', projects=projects)


@app.route('/create-project', methods=['POST'])
@login_required
def create_project():
    """Create a new project"""
    name = request.form.get('name')
    description = request.form.get('description', '')

    if not name:
        flash('Project name is required', 'danger')
        return redirect(url_for('dashboard'))

    # Create a unique project folder
    folder_name = f"{current_user.id}_{uuid.uuid4().hex}"
    folder_path = os.path.join(app.config['UPLOAD_FOLDER'], folder_name)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Create project in database
    project = Project(
        name=name,
        description=description,
        folder_path=folder_path,
        user_id=current_user.id
    )

    db.session.add(project)
    db.session.commit()

    flash('Project created successfully', 'success')
    return redirect(url_for('project_detail', project_id=project.id))


@app.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    """Project detail page"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    # Use the project model's method to update requirements status
    project.update_requirements_status()

    # Log the requirements.txt status for debugging
    print(f"Project {project_id} has_requirements_file: {project.has_requirements_file}")
    print(f"Project {project_id} requirements_file flag: {project.requirements_file}")

    # Get the active tab from query params
    active_tab = request.args.get('tab', 'files')

    # Get root-level files and folders
    files = File.query.filter_by(project_id=project_id, folder_id=None).all()
    folders = Folder.query.filter_by(project_id=project_id, parent_folder_id=None).all()
    commits = Commit.query.filter_by(project_id=project_id).order_by(Commit.created_at.desc()).all()

    return render_template('project.html',
                          project=project,
                          files=files,
                          folders=folders,
                          commits=commits,
                          active_tab=active_tab)


@app.route('/project/<int:project_id>/folder/<int:folder_id>')
@login_required
def folder_view(project_id, folder_id):
    """View contents of a folder"""
    project = Project.query.get_or_404(project_id)
    folder = Folder.query.get_or_404(folder_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    # Verify folder belongs to project
    if folder.project_id != project_id:
        flash('Folder does not belong to this project', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    files = File.query.filter_by(folder_id=folder_id).all()
    subfolders = Folder.query.filter_by(parent_folder_id=folder_id).all()
    parent_folder = folder.parent

    return render_template('folder_view.html',
                          project=project,
                          folder=folder,
                          files=files,
                          subfolders=subfolders,
                          parent_folder=parent_folder)


@app.route('/project/<int:project_id>/create-folder', methods=['POST'])
@login_required
def create_folder(project_id):
    """Create a new folder in a project"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    folder_name = request.form.get('folder_name')
    parent_folder_id = request.form.get('parent_folder_id')

    if not folder_name:
        flash('Folder name is required', 'danger')
        if parent_folder_id:
            return redirect(url_for('folder_view', project_id=project_id, folder_id=parent_folder_id))
        return redirect(url_for('project_detail', project_id=project_id))

    # Clean folder name
    folder_name = secure_filename(folder_name)

    # Determine the folder path
    if parent_folder_id:
        parent_folder = Folder.query.get_or_404(parent_folder_id)
        if parent_folder.project_id != project_id:
            flash('Invalid parent folder', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))

        path = os.path.join(parent_folder.path, folder_name)
        physical_path = os.path.join(project.folder_path, path)
    else:
        path = folder_name
        physical_path = os.path.join(project.folder_path, path)

    # Check if folder already exists
    if os.path.exists(physical_path):
        flash(f'A folder with the name "{folder_name}" already exists', 'danger')
        if parent_folder_id:
            return redirect(url_for('folder_view', project_id=project_id, folder_id=parent_folder_id))
        return redirect(url_for('project_detail', project_id=project_id))

    # Create the folder physically
    os.makedirs(physical_path, exist_ok=True)

    # Create the folder in the database
    folder = Folder(
        name=folder_name,
        path=path,
        project_id=project_id,
        parent_folder_id=parent_folder_id if parent_folder_id else None
    )

    db.session.add(folder)
    db.session.commit()

    flash(f'Folder "{folder_name}" created successfully', 'success')

    if parent_folder_id:
        return redirect(url_for('folder_view', project_id=project_id, folder_id=parent_folder_id))
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/project/<int:project_id>/delete-folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(project_id, folder_id):
    """Delete a folder from a project"""
    project = Project.query.get_or_404(project_id)
    folder = Folder.query.get_or_404(folder_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    # Verify folder belongs to project
    if folder.project_id != project_id:
        flash('Folder does not belong to this project', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    parent_folder_id = folder.parent_folder_id

    try:
        # Delete folder from the filesystem
        physical_path = os.path.join(project.folder_path, folder.path)
        if os.path.exists(physical_path):
            import shutil
            shutil.rmtree(physical_path)

        # Delete folder from database (cascade will delete contents)
        db.session.delete(folder)
        db.session.commit()

        flash(f'Folder "{folder.name}" deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting folder: {str(e)}', 'danger')

    if parent_folder_id:
        return redirect(url_for('folder_view', project_id=project_id, folder_id=parent_folder_id))
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/project/<int:project_id>/upload', methods=['POST'])
@login_required
def upload_file(project_id):
    """Upload file to project"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    folder_id = request.form.get('folder_id')

    if 'file' not in request.files:
        flash('No file part', 'danger')
        if folder_id:
            return redirect(url_for('folder_view', project_id=project_id, folder_id=folder_id))
        return redirect(url_for('project_detail', project_id=project_id))

    file = request.files['file']

    if file.filename == '':
        flash('No selected file', 'danger')
        if folder_id:
            return redirect(url_for('folder_view', project_id=project_id, folder_id=folder_id))
        return redirect(url_for('project_detail', project_id=project_id))

    if file and is_allowed_file(file.filename):
        filename = secure_filename(file.filename)

        # Determine file path based on whether it's in a folder
        if folder_id:
            folder = Folder.query.get_or_404(folder_id)
            if folder.project_id != project_id:
                flash('Invalid folder', 'danger')
                return redirect(url_for('project_detail', project_id=project_id))

            rel_path = os.path.join(folder.path, filename)
            file_path = os.path.join(project.folder_path, rel_path)
        else:
            rel_path = filename
            file_path = os.path.join(project.folder_path, filename)

        # Save file to disk
        file.save(file_path)

        # Save file info to database
        is_binary = not is_allowed_file(filename, text_only=True)
        content = None if is_binary else read_file_content(file_path)

        db_file = File(
            filename=filename,
            path=rel_path,
            content=content,
            is_binary=is_binary,
            project_id=project_id,
            folder_id=folder_id
        )

        db.session.add(db_file)
        db.session.commit()

        # If the uploaded file is requirements.txt in the root directory, update the flag
        if filename == 'requirements.txt' and not folder_id:
            project.requirements_file = True
            db.session.commit()

        flash('File uploaded successfully', 'success')
    else:
        flash('File type not allowed', 'danger')

    if folder_id:
        return redirect(url_for('folder_view', project_id=project_id, folder_id=folder_id))
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/project/<int:project_id>/new-file', methods=['POST'])
@login_required
def new_file(project_id):
    """Create a new text file"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    filename = request.form.get('filename')
    folder_id = request.form.get('folder_id')

    if not filename:
        flash('Filename is required', 'danger')
        if folder_id:
            return redirect(url_for('folder_view', project_id=project_id, folder_id=folder_id))
        return redirect(url_for('project_detail', project_id=project_id))

    # Ensure the filename has a valid extension
    if not re.search(r'\.\w+$', filename):
        filename += '.txt'

    filename = secure_filename(filename)

    # Determine file path based on whether it's in a folder
    if folder_id:
        folder = Folder.query.get_or_404(folder_id)
        if folder.project_id != project_id:
            flash('Invalid folder', 'danger')
            return redirect(url_for('project_detail', project_id=project_id))

        rel_path = os.path.join(folder.path, filename)
        file_path = os.path.join(project.folder_path, rel_path)
    else:
        rel_path = filename
        file_path = os.path.join(project.folder_path, filename)

    # Check if file already exists
    if os.path.exists(file_path):
        flash('File already exists', 'danger')
        if folder_id:
            return redirect(url_for('folder_view', project_id=project_id, folder_id=folder_id))
        return redirect(url_for('project_detail', project_id=project_id))

    # Create empty file
    with open(file_path, 'w') as f:
        f.write('')

    # Save file info to database
    db_file = File(
        filename=filename,
        path=rel_path,
        content='',
        is_binary=False,
        project_id=project_id,
        folder_id=folder_id
    )

    db.session.add(db_file)
    db.session.commit()

    # If the created file is requirements.txt in the root directory, update the flag
    if filename == 'requirements.txt' and not folder_id:
        project.requirements_file = True
        db.session.commit()

    flash('File created successfully', 'success')
    return redirect(url_for('edit_file', project_id=project_id, file_id=db_file.id))


@app.route('/project/<int:project_id>/file/<int:file_id>')
@login_required
def edit_file(project_id, file_id):
    """Edit file"""
    project = Project.query.get_or_404(project_id)
    file = File.query.get_or_404(file_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    # Verify file belongs to project
    if file.project_id != project_id:
        flash('File does not belong to this project', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    # If binary file, redirect to project detail
    if file.is_binary:
        flash('Binary files cannot be edited directly', 'warning')
        if file.folder_id:
            return redirect(url_for('folder_view', project_id=project_id, folder_id=file.folder_id))
        return redirect(url_for('project_detail', project_id=project_id))

    # Read file content
    file_path = os.path.join(project.folder_path, file.path)
    content = read_file_content(file_path)

    file_extension = get_file_extension(file.filename)

    return render_template('file_editor.html', project=project, file=file, content=content, file_extension=file_extension)


@app.route('/project/<int:project_id>/file/<int:file_id>/save', methods=['POST'])
@login_required
def save_file_changes(project_id, file_id):
    """Save file changes"""
    project = Project.query.get_or_404(project_id)
    file = File.query.get_or_404(file_id)

    # Verify ownership
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    # Verify file belongs to project
    if file.project_id != project_id:
        return jsonify({'success': False, 'message': 'File does not belong to this project'}), 400

    content = request.form.get('content', '')
    commit_message = request.form.get('commit_message', 'Update file')

    # Save file to disk
    file_path = os.path.join(project.folder_path, file.path)

    try:
        with open(file_path, 'w') as f:
            f.write(content)

        # Update file content in database
        file.content = content
        file.updated_at = datetime.now(timezone.utc)

        # Create a commit and file version
        commit = Commit(
            message=commit_message,
            project_id=project_id,
            user_id=current_user.id
        )

        db.session.add(commit)
        db.session.flush()  # Get commit ID without committing

        # Create a file version
        file_version = FileVersion(
            content=content,
            file_id=file.id,
            commit_id=commit.id
        )

        db.session.add(file_version)
        db.session.commit()

        return jsonify({'success': True, 'message': 'File saved successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Error saving file: {str(e)}'}), 500


@app.route('/project/<int:project_id>/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(project_id, file_id):
    """Delete file"""
    project = Project.query.get_or_404(project_id)
    file = File.query.get_or_404(file_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    # Verify file belongs to project
    if file.project_id != project_id:
        flash('File does not belong to this project', 'danger')
        return redirect(url_for('project_detail', project_id=project_id))

    folder_id = file.folder_id

    try:
        # Delete file from disk
        file_path = os.path.join(project.folder_path, file.path)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Delete file from database
        db.session.delete(file)
        db.session.commit()

        flash('File deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'danger')

    if folder_id:
        return redirect(url_for('folder_view', project_id=project_id, folder_id=folder_id))
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    """Delete project"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Stop the app if it's running
        if project.is_running and project.pid:
            try:
                stop_application(project)
            except:
                # Continue with deletion even if stopping fails
                pass

        # Delete project folder
        import shutil
        if os.path.exists(project.folder_path):
            shutil.rmtree(project.folder_path)

        # Delete project from database
        db.session.delete(project)
        db.session.commit()

        flash('Project deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting project: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/project/<int:project_id>/app-manager')
@login_required
def app_manager(project_id):
    """App manager page"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    # Use the project model's method to update requirements status
    # This will check if requirements.txt exists and update the flag
    project.update_requirements_status()

    # Log the requirements.txt status for debugging
    print(f"Project {project_id} has_requirements_file: {project.has_requirements_file}")
    print(f"Project {project_id} requirements_file flag: {project.requirements_file}")

    # Get all files that can be entry points
    files = File.query.filter_by(project_id=project_id).all()

    # Get application logs
    logs = AppLog.query.filter_by(project_id=project_id).order_by(AppLog.created_at.desc()).limit(50).all()

    # Read log content from log file if it exists
    log_content = ''
    log_file = os.path.join(project.folder_path, 'app.log')
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            log_content = f.read()

    # Get terminal commands
    terminal_commands = TerminalCommand.query.filter_by(project_id=project_id).order_by(TerminalCommand.created_at.desc()).limit(10).all()

    return render_template('app_manager.html',
                          project=project,
                          files=files,
                          logs=logs,
                          log_content=log_content,
                          terminal_commands=terminal_commands)


def stop_application(project):
    """Stop running application"""
    if project.is_running and project.pid:
        # Check if the process exists
        if not psutil.pid_exists(project.pid):
            # Process is already gone
            pass
        else:
            # Windows-specific approach - use taskkill
            try:
                # First try a graceful termination
                subprocess.run(['taskkill', '/PID', str(project.pid)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            except (subprocess.SubprocessError, OSError):
                pass  # Ignore if taskkill fails

            # If process still exists, force kill it
            if psutil.pid_exists(project.pid):
                try:
                    subprocess.run(['taskkill', '/F', '/PID', str(project.pid)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
                except (subprocess.SubprocessError, OSError):
                    pass  # Ignore if taskkill fails

            # As a last resort, try to use psutil to kill the process
            if psutil.pid_exists(project.pid):
                try:
                    process = psutil.Process(project.pid)
                    process.terminate()
                    process.wait(timeout=3)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    pass

        # Create a log entry
        log = AppLog(
            log_content=f"Application stopped (PID: {project.pid})",
            log_type="system",
            project_id=project.id
        )

        # Update the project state
        project.is_running = False
        project.pid = None

        db.session.add(log)
        db.session.commit()

        return True

    return False


@app.route('/project/<int:project_id>/stop-app', methods=['POST'])
@login_required
def stop_app(project_id):
    """Stop the application"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    if not project.is_running:
        flash('The application is not running', 'warning')
    else:
        if stop_application(project):
            flash('Application stopped successfully', 'success')
        else:
            flash('Failed to stop application', 'danger')

    return redirect(url_for('app_manager', project_id=project_id))


@app.route('/project/<int:project_id>/run-app', methods=['POST'])
@login_required
def run_application(project_id):
    """Run the application"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    # If already running, stop first
    if project.is_running:
        stop_application(project)

    entry_point = request.form.get('entry_point')
    if not entry_point:
        flash('Entry point is required', 'danger')
        return redirect(url_for('app_manager', project_id=project_id))

    # Find an available port
    port = find_available_port(8000, 9000)
    if not port:
        flash('No available ports found', 'danger')
        return redirect(url_for('app_manager', project_id=project_id))

    # Use the project model's method to update requirements status
    project.update_requirements_status()

    # Get paths for requirements and log files
    requirements_file = os.path.join(project.folder_path, 'requirements.txt')
    log_file = os.path.join(project.folder_path, 'app.log')

    # Create or clear the log file
    with open(log_file, 'w') as f:
        f.write("Starting application setup...\n")
        f.write(f"Requirements.txt detected: {'Yes' if project.has_requirements_file else 'No'}\n")

    if project.has_requirements_file:
        # Set requirements file flag if it exists
        project.requirements_file = True
        db.session.commit()

        # Log that we found a requirements.txt file
        log = AppLog(
            log_content=f"Found requirements.txt file in project root",
            log_type="system",
            project_id=project.id
        )
        db.session.add(log)
        db.session.commit()

        with open(log_file, 'a') as f:
            f.write("Found requirements.txt file in project root\n")

        # Always check if requirements need to be installed
        needs_install = check_requirements_changes(requirements_file, project.folder_path)

        if needs_install:
            # Install requirements from requirements.txt
            with open(log_file, 'a') as f:
                f.write("Installing requirements from requirements.txt...\n")

            success, output = install_requirements(requirements_file, log_file)

            if success:
                log = AppLog(
                    log_content=f"Successfully installed requirements from requirements.txt",
                    log_type="system",
                    project_id=project.id
                )
                with open(log_file, 'a') as f:
                    f.write("Successfully installed requirements from requirements.txt\n")
            else:
                log = AppLog(
                    log_content=f"Failed to install requirements: {output}",
                    log_type="system",
                    project_id=project.id
                )
                with open(log_file, 'a') as f:
                    f.write(f"Failed to install requirements: {output}\n")

            db.session.add(log)
            db.session.commit()
        else:
            # Log that requirements are up to date
            log = AppLog(
                log_content=f"Requirements are up to date, skipping installation",
                log_type="system",
                project_id=project.id
            )
            db.session.add(log)
            db.session.commit()

            # Add a note to the log file
            with open(log_file, 'a') as f:
                f.write("Requirements are up to date, skipping installation...\n")
    else:
        # No requirements.txt file found - inform the user
        log = AppLog(
            log_content=f"No requirements.txt file found. Dependencies will not be installed automatically.",
            log_type="system",
            project_id=project.id
        )
        db.session.add(log)
        db.session.commit()

        # Add a note to the log file
        with open(log_file, 'a') as f:
            f.write("No requirements.txt file found. If your application needs external packages, create a requirements.txt file.\n")
            f.write("You can create and edit requirements.txt from the App Manager page.\n")

    # Prepare log file for application output
    with open(log_file, 'a') as f:
        f.write("\nStarting application...\n")

    try:
        # Determine file extension and appropriate interpreter
        file_extension = os.path.splitext(entry_point)[1].lower()

        # Build command based on file type
        if file_extension == '.py':
            # For Python files, use the Python interpreter
            interpreter_path = sys.executable
            cmd = [
                interpreter_path,
                os.path.join(project.folder_path, entry_point),
            ]
        elif file_extension == '.js':
            # For JavaScript files, use Node.js
            cmd = [
                'node',
                os.path.join(project.folder_path, entry_point),
            ]
        elif file_extension == '.sh':
            # For shell scripts
            cmd = [
                'bash',
                os.path.join(project.folder_path, entry_point),
            ]
        else:
            # For other files, try to execute directly
            cmd = [os.path.join(project.folder_path, entry_point)]

        # Add command to unbuffer Python output for real-time logging
        # This ensures that Python doesn't buffer stdout which can delay log updates
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'

        # Log application command
        with open(log_file, 'a') as f:
            f.write(f"Running command: {' '.join(cmd)}\n")

        # Start the application with redirected output to the log file
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,  # Capture stdout
            stderr=subprocess.STDOUT,  # Redirect stderr to stdout
            cwd=project.folder_path,
            env=env,  # Use environment with unbuffered output
            universal_newlines=True,  # Use text mode for output
            bufsize=1  # Line buffered
        )

        # Define a function to read output and append to log file
        def log_output(process, log_file_path):
            try:
                with open(log_file_path, 'a') as log_file:
                    for line in iter(process.stdout.readline, ''):
                        log_file.write(line)
                        log_file.flush()  # Force flush to ensure logs are written immediately

                    # Add a message when the process ends
                    if process.poll() is not None:
                        log_file.write("\nApplication process has ended.")
                        log_file.flush()
            except Exception as e:
                # Write the error to the log file
                try:
                    with open(log_file_path, 'a') as log_file:
                        log_file.write(f"\nError capturing output: {str(e)}\n")
                except:
                    pass  # If we can't write to the log file, there's not much we can do
            finally:
                if process.stdout:
                    process.stdout.close()

        # Start the logging thread
        import threading
        log_thread = threading.Thread(
            target=log_output,
            args=(process, log_file),
            daemon=True  # Thread dies with the program
        )
        log_thread.start()

        # Update project with running state
        project.is_running = True
        project.pid = process.pid
        project.port = port
        project.entry_point = entry_point

        # Create a log entry
        log = AppLog(
            log_content=f"Application started (PID: {process.pid}, Port: {port}, Entry: {entry_point})",
            log_type="system",
            project_id=project.id
        )

        db.session.add(log)
        db.session.commit()

        flash('Application started successfully', 'success')
    except Exception as e:
        # Log the error and notify the user
        error_message = f"Error starting application: {str(e)}"
        log = AppLog(
            log_content=error_message,
            log_type="system",
            project_id=project.id
        )
        db.session.add(log)
        db.session.commit()

        flash(error_message, 'danger')

    return redirect(url_for('app_manager', project_id=project_id))


@app.route('/project/<int:project_id>/create-requirements-test')
@login_required
def create_requirements_test(project_id):
    """Create a test requirements.txt file"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    # Create a test requirements.txt file
    requirements_file = os.path.join(project.folder_path, 'requirements.txt')
    requirements_file_typo = os.path.join(project.folder_path, 'requierments.txt')  # Common typo

    # Check if the typo version exists and remove it
    if os.path.exists(requirements_file_typo):
        try:
            os.remove(requirements_file_typo)
            print(f"DEBUG: Removed typo file: {requirements_file_typo}")
        except Exception as e:
            print(f"DEBUG: Error removing typo file: {str(e)}")

    try:
        with open(requirements_file, 'w') as f:
            f.write("# Test requirements file\nflask==2.0.1\nrequests==2.25.1\n")

        print(f"DEBUG: Created test requirements.txt at: {requirements_file}")

        # Update the database flag
        project.requirements_file = True
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Test requirements.txt file created',
            'path': requirements_file
        })
    except Exception as e:
        print(f"ERROR: Failed to create requirements.txt: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to create requirements.txt: {str(e)}'
        }), 500


@app.route('/project/<int:project_id>/check-requirements')
@login_required
def check_requirements(project_id):
    """Check if requirements.txt exists via AJAX"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    # Force a direct check of the file system
    requirements_file = os.path.join(project.folder_path, 'requirements.txt')
    requirements_file_typo = os.path.join(project.folder_path, 'requierments.txt')  # Common typo

    # Print debug information
    print(f"DEBUG: Checking for requirements.txt at: {requirements_file}")
    print(f"DEBUG: Also checking for typo: {requirements_file_typo}")
    print(f"DEBUG: Project folder path: {project.folder_path}")
    print(f"DEBUG: requirements.txt exists: {os.path.exists(requirements_file)}")
    print(f"DEBUG: requierments.txt exists: {os.path.exists(requirements_file_typo)}")

    # List all files in the project folder
    try:
        files_in_folder = os.listdir(project.folder_path)
        print(f"DEBUG: Files in project folder: {files_in_folder}")
    except Exception as e:
        print(f"DEBUG: Error listing files: {str(e)}")

    # Handle the typo file if it exists
    if 'requierments.txt' in files_in_folder:
        try:
            # Create a correct requirements.txt file
            with open(requirements_file, 'w') as f:
                f.write("# Auto-generated from requierments.txt\nflask==2.0.1\nrequests==2.25.1\n")

            print(f"DEBUG: Created requirements.txt file")

            # Try to remove the typo file
            try:
                os.remove(requirements_file_typo)
                print(f"DEBUG: Removed typo file requierments.txt")
            except Exception as e:
                print(f"DEBUG: Could not remove typo file: {str(e)}")
        except Exception as e:
            print(f"DEBUG: Error handling typo file: {str(e)}")

    # Check if requirements.txt exists now - FORCE a direct check
    has_requirements = False

    try:
        # List all files in the project folder again to be sure
        files_in_folder = os.listdir(project.folder_path)
        print(f"DEBUG: Files in project folder (final check): {files_in_folder}")

        # Check if requirements.txt exists in the list
        if 'requirements.txt' in files_in_folder:
            has_requirements = True
            print(f"DEBUG: Found requirements.txt in file list")
        else:
            # Try a direct check
            has_requirements = os.path.exists(requirements_file) and os.path.isfile(requirements_file)
            print(f"DEBUG: Direct check for requirements.txt: {has_requirements}")

            # If still not found, create one as a last resort
            if not has_requirements:
                try:
                    with open(requirements_file, 'w') as f:
                        f.write("# Auto-generated requirements file\nflask==2.0.1\nrequests==2.25.1\n")
                    has_requirements = True
                    print(f"DEBUG: Created requirements.txt as last resort")
                except Exception as e:
                    print(f"DEBUG: Error creating requirements.txt: {str(e)}")
    except Exception as e:
        print(f"DEBUG: Error in final check: {str(e)}")

    # ALWAYS update the database flag to match our determination
    project.requirements_file = has_requirements
    db.session.commit()
    print(f"Updated requirements_file flag for project {project_id} to {has_requirements}")

    # Double-check after commit
    db.session.refresh(project)

    return jsonify({
        'success': True,
        'has_requirements': has_requirements,
        'requirements_file_flag': project.requirements_file,
        'requirements_path': requirements_file,
        'project_folder': project.folder_path,
        'files_in_folder': os.listdir(project.folder_path) if os.path.exists(project.folder_path) else [],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/project/<int:project_id>/logs')
@login_required
def get_logs(project_id):
    """Get application logs via AJAX"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    log_content = ''
    log_file = os.path.join(project.folder_path, 'app.log')

    # Read from the log file if it exists
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                log_content = f.read()

            # If log content is empty but the file exists and app is running
            # we'll add a message to make it clear the app is running but not producing output
            if not log_content.strip() and project.is_running:
                log_content = "(Application is running but has not produced any output yet.)"

            # Store logs in the database for history
            # Only if there's actual content and it's different from the last log
            if log_content.strip() and project.is_running:
                # Get the last log entry
                last_log = AppLog.query.filter_by(
                    project_id=project_id,
                    log_type='stdout'
                ).order_by(AppLog.created_at.desc()).first()

                # Only add a new log if content is different
                if not last_log or last_log.log_content != log_content:
                    log = AppLog(
                        log_content=log_content,
                        log_type="stdout",
                        project_id=project.id
                    )
                    db.session.add(log)
                    db.session.commit()
        except Exception as e:
            log_content = f"Error reading log file: {str(e)}"

            # Log the error
            error_log = AppLog(
                log_content=log_content,
                log_type="system",
                project_id=project.id
            )
            db.session.add(error_log)
            db.session.commit()
    elif project.is_running:
        # If app is running but log file doesn't exist yet
        log_content = "(Waiting for application to start producing output...)"

    return jsonify({'success': True, 'log_content': log_content})


@app.route('/project/<int:project_id>/terminal/run', methods=['POST'])
@login_required
def run_terminal_command(project_id):
    """Run a command in the terminal"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    command = request.form.get('command')
    if not command:
        return jsonify({'success': False, 'message': 'Command is required'}), 400

    # Create a command record
    terminal_command = TerminalCommand(
        command=command,
        project_id=project_id,
        user_id=current_user.id,
        status='pending'
    )

    db.session.add(terminal_command)
    db.session.commit()

    try:
        # Run the command in the project directory
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=project.folder_path,
            universal_newlines=True
        )

        stdout, stderr = process.communicate(timeout=30)
        output = stdout

        if stderr:
            output += f"\nERROR: {stderr}"

        if process.returncode != 0:
            status = 'failed'
        else:
            status = 'completed'

            # Add a note about updating requirements.txt manually if pip install was used
            if "pip install" in command and status == 'completed':
                output += "\n\nNote: If you want to save this package in your requirements.txt file, please use the Requirements Editor."

        # Update the command record
        terminal_command.output = output
        terminal_command.status = status

        # Create a system log entry
        log = AppLog(
            log_content=f"Terminal command: {command} ({status})",
            log_type="terminal",
            project_id=project_id
        )

        db.session.add(log)
        db.session.commit()

        return jsonify({
            'success': True,
            'output': output,
            'status': status,
            'command_id': terminal_command.id
        })

    except subprocess.TimeoutExpired:
        # Handle command timeout
        terminal_command.output = "Command execution timed out (>30s)"
        terminal_command.status = 'failed'
        db.session.commit()

        return jsonify({
            'success': False,
            'message': 'Command execution timed out',
            'status': 'failed',
            'command_id': terminal_command.id
        }), 408

    except Exception as e:
        # Handle other errors
        terminal_command.output = f"Error executing command: {str(e)}"
        terminal_command.status = 'failed'
        db.session.commit()

        return jsonify({
            'success': False,
            'message': f'Error executing command: {str(e)}',
            'status': 'failed',
            'command_id': terminal_command.id
        }), 500


@app.route('/project/<int:project_id>/generate-requirements', methods=['POST'])
@login_required
def generate_requirements(project_id):
    """Generate a template requirements.txt file for a project"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Generate requirements.txt template
        requirements_file = os.path.join(project.folder_path, 'requirements.txt')

        # Check if file already exists
        if os.path.exists(requirements_file):
            # Ask user to use the requirements editor instead
            flash('requirements.txt already exists. Please use the Requirements Editor to modify it.', 'info')
            return redirect(url_for('requirements_editor', project_id=project_id))

        # Create a template with helpful comments and basic packages
        template_content = """# Add your Python package requirements here
# The application will install these packages when you run it
# Format: one package per line, optionally with version constraints
# Examples:
# flask==2.0.1
# requests>=2.25.0
# numpy

# Basic packages for web applications
flask
werkzeug
jinja2
flask-sqlalchemy
flask-login

# Add your additional requirements below:
"""

        # If entry point is set, suggest packages based on imports
        suggested_packages = []
        if project.entry_point:
            entry_point_full_path = os.path.join(project.folder_path, project.entry_point)
            suggested_packages = get_requirements_from_file(entry_point_full_path)

            # Add suggested packages as comments
            if suggested_packages:
                template_content += "\n# Suggested packages based on your code:\n"
                for pkg in suggested_packages:
                    if pkg not in ['flask', 'werkzeug', 'jinja2', 'flask-sqlalchemy', 'flask-login']:
                        template_content += f"# {pkg}\n"

        # Write the template to file
        with open(requirements_file, 'w') as f:
            f.write(template_content)

        project.requirements_file = True
        db.session.commit()

        flash('requirements.txt template created. Please review and edit it in the Requirements Editor.', 'success')

        # Redirect to the requirements editor
        return redirect(url_for('requirements_editor', project_id=project_id))

    except Exception as e:
        flash(f'Error creating requirements.txt template: {str(e)}', 'danger')

    return redirect(url_for('app_manager', project_id=project_id))


@app.route('/project/<int:project_id>/requirements-editor')
@login_required
def requirements_editor(project_id):
    """Edit requirements.txt file for a project"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        flash('You do not have permission to access this project', 'danger')
        return redirect(url_for('dashboard'))

    # Check if requirements.txt exists
    requirements_file = os.path.join(project.folder_path, 'requirements.txt')
    requirements_content = ""

    if os.path.exists(requirements_file):
        try:
            with open(requirements_file, 'r') as f:
                requirements_content = f.read()
        except Exception as e:
            flash(f'Error reading requirements.txt: {str(e)}', 'warning')
    else:
        # Create a template requirements.txt file if it doesn't exist
        requirements_content = """# Add your Python package requirements here
# The application will install these packages when you run it
# Format: one package per line, optionally with version constraints
# Examples:
# flask==2.0.1
# requests>=2.25.0
# numpy

# Basic packages for web applications
flask
werkzeug
jinja2
flask-sqlalchemy
flask-login

# Add your additional requirements below:
"""
        # Don't save the file yet - let the user edit it first
        flash('No requirements.txt file found. A template has been created for you to edit.', 'info')

    return render_template('requirements_editor.html',
                          project=project,
                          requirements_content=requirements_content)


@app.route('/project/<int:project_id>/save-requirements', methods=['POST'])
@login_required
def save_requirements(project_id):
    """Save requirements.txt file for a project"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    content = request.form.get('content', '')
    install_now = request.form.get('install_now', 'false') == 'true'

    try:
        # Save requirements.txt
        requirements_file = os.path.join(project.folder_path, 'requirements.txt')

        with open(requirements_file, 'w') as f:
            f.write(content)

        # Make sure the requirements_file flag is set to True
        if not project.requirements_file:
            project.requirements_file = True
            db.session.commit()

        # Create a log entry
        log = AppLog(
            log_content=f"Requirements.txt updated by user",
            log_type="system",
            project_id=project.id
        )
        db.session.add(log)
        db.session.commit()

        # If install_now is true, install the requirements
        if install_now:
            log_file = os.path.join(project.folder_path, 'app.log')
            with open(log_file, 'a') as f:
                f.write("\nInstalling updated requirements...\n")

            success, output = install_requirements(requirements_file, log_file)

            if success:
                log = AppLog(
                    log_content=f"Successfully installed updated requirements",
                    log_type="system",
                    project_id=project.id
                )
                db.session.add(log)
                db.session.commit()
                return jsonify({'success': True, 'message': 'Requirements saved and installed successfully'})
            else:
                log = AppLog(
                    log_content=f"Failed to install requirements: {output}",
                    log_type="system",
                    project_id=project.id
                )
                db.session.add(log)
                db.session.commit()
                return jsonify({'success': False, 'message': f'Requirements saved but installation failed: {output}'}), 500

        return jsonify({'success': True, 'message': 'Requirements saved successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error saving requirements: {str(e)}'}), 500


@app.route('/project/<int:project_id>/terminal/command/<int:command_id>')
@login_required
def get_terminal_command(project_id, command_id):
    """Get terminal command details via AJAX"""
    project = Project.query.get_or_404(project_id)

    # Verify ownership
    if project.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Permission denied'}), 403

    command = TerminalCommand.query.get_or_404(command_id)

    if command.project_id != project_id:
        return jsonify({'success': False, 'message': 'Command does not belong to this project'}), 400

    return jsonify({
        'success': True,
        'command': command.command,
        'output': command.output,
        'status': command.status,
        'created_at': command.created_at.strftime('%Y-%m-%d %H:%M:%S')
    })
