from flask import Flask
from .routes import admin_bp

app = Flask(__name__)
app.register_blueprint(admin_bp)

if __name__ == '__main__':
    app.run(debug=True)
