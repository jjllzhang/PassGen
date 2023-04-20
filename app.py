# Import necessary dependencies
from flask import Flask, request, jsonify, render_template
from hdkf import *
from datetime import datetime
import base64

# Create a Flask app instance
app = Flask(__name__)


# Define a route for the home page and handle GET and POST requests
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        # Retrieve master key, scene, and password length from the form data submitted by the user
        master_key = request.form['master-key']
        scene = request.form['scene']
        length = int(request.form['length'])

        # Call generate_password function to generate a new password based on the user input
        password = generate_password(master_key, scene, length)

        # Return the generated password as a JSON object
        return jsonify({'password': password})

    # When receiving a GET request, render an HTML template for the index page
    return render_template('index.html')


# Define a function for generating passwords using HKDF algorithm
def generate_password(master_key, scene, length):
    # Get current date and time as a string
    now = datetime.now()
    time_str = now.strftime('%Y-%m-%d %H:%M:%S')

    # Use the current datetime string as the salt for the HKDF algorithm
    salt = time_str.encode('utf-8')

    # Convert the master key and scene to bytes and use them as the input key material (IKM)
    ikm = master_key.encode('utf-8')
    info = scene.encode('utf-8')

    # Generate a new password bytes using HKDF algorithm with the salt, IKM, and scene data
    password_bytes = hkdf(salt, ikm, info, length)

    # Encode the password bytes to base64 format and convert it to a string
    password = base64.b64encode(password_bytes).decode('utf-8')

    # Return the password with the specified length
    return password[:length]


# Start the Flask app if this script is executed as the main program
if __name__ == '__main__':
    app.run(debug=True)
