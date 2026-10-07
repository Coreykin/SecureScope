"""Example source code for SecureScope to scan.
Contains intentional security issues. Do not deploy.
"""

from flask import Flask

app = Flask(__name__)
app.config["SECRET_KEY"] = "demo-secret-do-not-use"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False

@app.route("/")
def home():
    return "SecureScope demonstration application"

if __name__ == "__main__":
    app.run(debug=True)
