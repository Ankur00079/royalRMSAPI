from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.secret_key = 'your_secret_key'
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
    cur.execute("""SELECT * FROM accounts WHERE id = %s""", (id,))
    data = cur.fetchall()
    cur.close()
    return jsonify(data)


@app.route("/register", methods=["POST"])
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


@app.route("/login", methods=["POST"])
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
            return jsonify({"message": "Login successfully"})
        return jsonify({"message": "Invalid Password"})
    return jsonify({"message": "Account not found"})


@app.route("/user/<int:id>", methods=["PUT"])
def update_user(id):
    cur = mysql.connection.cursor()
    name = request.json["name"]
    email = request.json["email"]
    cur.execute(
        """UPDATE accounts SET name = %s, email = %s WHERE id = %s""", (name, email, id)
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
