# Web Development Environment

This project provides a web-based development environment with package management capabilities.

## Requirements Management

1. When you run the application using `python main.py`, the system will:
   - Check if a `requirements.txt` file exists
   - If it exists, ask for your confirmation before installing packages
   - Install the packages using pip
   - Run the application

2. The `requirements.txt` file is fully under your control:
   - You can create and edit it through the web interface or manually
   - You can add, remove, or modify package requirements
   - You can specify version constraints (e.g., `flask==2.0.1`, `requests>=2.25.0`)
   - One package per line

## Example requirements.txt

```
# Add your Python package requirements here
# The application will install these packages when you run it
# Format: one package per line, optionally with version constraints

flask
werkzeug
jinja2
flask-sqlalchemy
flask-login
requests
pandas
```

## Virtual Environment

This project uses a virtual environment named 'hr'. To activate it:

- Windows: `hr\Scripts\activate`
- Linux/Mac: `source hr/bin/activate`

Always make sure the virtual environment is activated before running the application.
