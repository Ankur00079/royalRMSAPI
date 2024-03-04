import datetime
from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import jwt

app = Flask(__name__)

app.secret_key = "RoyalRMSAnkurAndParth"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "1234"
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_DB"] = "royalrms"

mysql = MySQL(app)
bcrypt = Bcrypt(app)


@app.route("/")
def hello_world():
    return "Hello World"


@app.route("/users", methods=["GET"])
def get_users():
    cur = mysql.connection.cursor()
    cur.execute("""SELECT name, email FROM accounts""")
    data = cur.fetchall()
    cur.close()
    return jsonify(data)


@app.route("/user/<int:id>", methods=["GET"])
def get_user_by_id(id):
    cur = mysql.connection.cursor()
    cur.execute("""SELECT name, email FROM accounts WHERE id = %s""", (id,))
    data = cur.fetchall()
    cur.close()
    return jsonify(data)


@app.route("/api/auth/register", methods=["POST"])
def register():
    cur = mysql.connection.cursor()
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    cur.execute(
        """INSERT INTO accounts (name, email, password) VALUES (%s, %s, %s)""",
        (name, email, hashed_password),
    )
    mysql.connection.commit()
    cur.close()
    return jsonify({"message": "Registered successfully"})


@app.route("/api/auth/login", methods=["POST"])
def login():
    cur = mysql.connection.cursor()
    email = request.json["email"]
    password = request.json["password"]
    cur = mysql.connection.cursor()
    cur.execute("""SELECT * FROM accounts WHERE email = %s""", (email,))
    account = cur.fetchone()
    cur.close()
    if account:
        # return jsonify(account[-1])
        hashed_password = account[-1]
        is_valid = bcrypt.check_password_hash(hashed_password, password)
        if is_valid:
            token = jwt.encode(
                {
                    "user_id": account[0],
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
                },
                app.config["SECRET_KEY"],
                algorithm="HS256",
            )
            return jsonify(
                {"status": 200, "message": "Login successfully", "token": token}
            )
        return jsonify({"message": "Invalid Password"})
    return jsonify({"message": "Account not found"})


@app.route("/api/auth/user", methods=["PUT"])
def update_user():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Token missing'}), 401
    
    try:
        payload = jwt.decode(token.split()[1], app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    
    cur = mysql.connection.cursor()
    name = request.json["name"]
    email = request.json["email"]
    cur.execute(
        """UPDATE accounts SET name = %s, email = %s WHERE id = %s""", (name, email, user_id)
    )
    mysql.connection.commit()
    cur.close()
    return jsonify({"message": "Data updated successfully"})


@app.route("/user/<int:id>", methods=["DELETE"])
def delete_user(id):
    cur = mysql.connection.cursor()
    cur.execute("""DELETE FROM accounts WHERE id = %s""", (id,))
    mysql.connection.commit()
    cur.close()
    return jsonify({"message": "Data deleted successfully"})


if __name__ == "__main__":
    app.run(debug=True)
