import os
import socket
import ast
import importlib
import subprocess
import sys
from werkzeug.datastructures import FileStorage

def get_file_extension(filename):
    """Get the file extension (lowercase) from a filename"""
    if '.' in filename:
        return filename.rsplit('.', 1)[1].lower()
    return ''

def is_allowed_file(filename, text_only=False):
    """Check if a file is allowed based on its extension"""
    if text_only:
        # Only allow text-based files
        text_extensions = {
            'txt', 'md', 'py', 'js', 'html', 'css', 'json', 'xml', 'csv',
            'yml', 'yaml', 'ini', 'cfg', 'conf', 'sh', 'bat', 'ps1',
            'c', 'cpp', 'h', 'hpp', 'java', 'rb', 'php', 'pl', 'go',
            'ts', 'jsx', 'tsx', 'vue', 'sql', 'r'
        }
        return get_file_extension(filename) in text_extensions

    # Exclude binary and potentially harmful files
    excluded_extensions = {
        'exe', 'dll', 'so', 'dylib', 'bin', 'msi', 'apk', 'dmg',
        'iso', 'img', 'jar', 'war', 'ear'
    }
    return get_file_extension(filename) not in excluded_extensions

def save_file(file_storage, filepath):
    """Save a file from FileStorage to disk"""
    if isinstance(file_storage, FileStorage):
        file_storage.save(filepath)
        return True
    return False

def read_file_content(filepath):
    """Read file content safely"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        # Try with a different encoding
        try:
            with open(filepath, 'r', encoding='latin-1') as f:
                return f.read()
        except:
            return None
    except Exception:
        return None

def is_port_in_use(port):
    """Check if a port is in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def find_available_port(start_port, end_port):
    """Find an available port in the given range"""
    for port in range(start_port, end_port + 1):
        if not is_port_in_use(port):
            return port
    return None

def extract_imports_from_file(file_path):
    """Extract imported modules from a Python file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = f.read()

        tree = ast.parse(file_content)
        imports = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.add(name.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split('.')[0])

        # Filter out standard library modules
        third_party_imports = set()
        for module_name in imports:
            try:
                module = importlib.import_module(module_name)
                if module.__file__ and 'site-packages' in module.__file__:
                    third_party_imports.add(module_name)
            except (ImportError, AttributeError):
                # If we can't import it, assume it's a third-party module
                third_party_imports.add(module_name)

        return third_party_imports
    except Exception as e:
        print(f"Error extracting imports: {str(e)}")
        return set()

def get_requirements_from_file(file_path):
    """Get requirements from a Python file by extracting imports"""
    if not os.path.exists(file_path):
        return []

    # Only process Python files
    if not file_path.endswith('.py'):
        return []

    imports = extract_imports_from_file(file_path)

    # Add basic requirements
    requirements = ['flask', 'werkzeug', 'jinja2', 'flask-sqlalchemy', 'flask-login']

    # Add extracted third-party modules
    requirements.extend(list(imports))

    # Remove duplicates and sort
    requirements = sorted(set(requirements))

    return requirements


def check_requirements_file_exists(project_folder):
    """Check if requirements.txt exists in the project folder

    Args:
        project_folder: Path to project folder

    Returns:
        bool: True if requirements.txt exists, False otherwise
    """
    requirements_file = os.path.join(project_folder, 'requirements.txt')
    return os.path.exists(requirements_file) and os.path.isfile(requirements_file)


def check_requirements_changes(requirements_file, project_folder):
    """Check if requirements.txt has been modified and needs to be reinstalled

    Args:
        requirements_file: Path to requirements.txt file
        project_folder: Path to project folder

    Returns:
        bool: True if requirements need to be reinstalled
    """
    # If requirements file doesn't exist, nothing to install
    if not os.path.exists(requirements_file):
        return False

    # Check if the requirements hash file exists
    hash_file = os.path.join(project_folder, '.requirements_hash')

    # Read current requirements content
    try:
        with open(requirements_file, 'r') as f:
            current_content = f.read().strip()
    except Exception:
        # If we can't read the file, assume it's corrupted and don't install
        return False

    # If requirements file exists but is empty, don't install
    if not current_content:
        return False

    # If hash file doesn't exist, this is the first time we're seeing this requirements file
    # So we need to install the packages
    if not os.path.exists(hash_file):
        # Create hash file with current content
        try:
            with open(hash_file, 'w') as f:
                f.write(current_content)
            return True
        except Exception:
            # If we can't write the hash file, still try to install
            return True

    # Read previous requirements hash
    try:
        with open(hash_file, 'r') as f:
            previous_content = f.read().strip()
    except Exception:
        # If we can't read the hash file, assume it's corrupted and reinstall
        try:
            with open(hash_file, 'w') as f:
                f.write(current_content)
            return True
        except Exception:
            # If we can't write the hash file either, still try to install
            return True

    # If content has changed, update hash and return True
    if current_content != previous_content:
        try:
            with open(hash_file, 'w') as f:
                f.write(current_content)
        except Exception:
            pass  # Ignore errors writing the hash file
        return True

    return False


def install_requirements(requirements_file, log_file=None):
    """Install packages from requirements.txt

    Args:
        requirements_file: Path to requirements.txt file
        log_file: Optional path to log file to write output

    Returns:
        tuple: (success, output)
    """
    if not os.path.exists(requirements_file):
        return False, "Requirements file not found"

    try:
        # Use the same Python interpreter that's running the app
        python_executable = sys.executable

        # Run pip install with the requirements file
        cmd = [
            python_executable,
            "-m",
            "pip",
            "install",
            "-r",
            requirements_file
        ]

        # Execute the command
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        output, _ = process.communicate()

        # Write to log file if provided
        if log_file and output:
            with open(log_file, 'a') as f:
                f.write("\n--- Installing requirements ---\n")
                f.write(output)
                f.write("\n--- End of requirements installation ---\n")

        # Return success based on return code
        return process.returncode == 0, output

    except Exception as e:
        error_msg = f"Error installing requirements: {str(e)}"

        # Write error to log file if provided
        if log_file:
            with open(log_file, 'a') as f:
                f.write("\n--- Error installing requirements ---\n")
                f.write(error_msg)
                f.write("\n--- End of error ---\n")

        return False, error_msg
