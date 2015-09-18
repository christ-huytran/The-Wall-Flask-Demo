from flask import Flask, render_template, redirect, url_for, session, request, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re
import time
from time import mktime
from datetime import datetime
EMAIL_REGEX = re.compile(r'^[a-za-z0-9\.\+_-]+@[a-za-z0-9\._-]+\.[a-za-z]*$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = '=\xb3\xb0iAb\x93\xec\x9f\x0f\xde\xf3\x06R\xd8\xa0*\x1fh\xd7%Q\x88\xaf'
mysql = MySQLConnector('the_wall_flask')

@app.route('/')
def index():
	return render_template('signup.html')

@app.route('/users', methods=['POST'])
def create():
	error = False
	email = request.form['email']
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	password = request.form['password']
	password_confirmation = request.form['password_confirmation']

	if len(first_name) < 1:
		error = True
		flash('First name cannot be blank', 'danger')
	if len(last_name) < 1:
		error = True
		flash('Last name cannot be blank', 'danger')
	if len(email) < 1:
		error = True
		flash('Email cannot be blank', 'danger')
	if len(password) < 1:
		error = True
		flash('Password cannot be blank', 'danger')
	if password != password_confirmation:
		error = True
		flash('Passwords do not match', 'danger')
	if not EMAIL_REGEX.match(email):
		error = True
		flash('Email is invalid', 'danger')

	if error:
		return redirect(url_for('index'))
	# run validations and if they are successful we can create the password hash with bcrypt
	pw_hash = bcrypt.generate_password_hash(password)
	
	# now we insert the new user into the database
	insert_query = "INSERT INTO users (email, first_name, last_name, password, created_at) VALUES ('{}', '{}', '{}', '{}', NOW())".format(email, first_name, last_name, pw_hash)
	mysql.run_mysql_query(insert_query)
	flash("You've successfully registered!", 'success')
	return redirect(url_for('signin'))

@app.route('/signin', methods=['POST','GET'])
def signin():
	if request.method == 'GET':
		return render_template('signin.html')
	email = request.form['email']
	password = request.form['password']
	user_query = "SELECT * FROM users WHERE email = '{}' LIMIT 1".format(email)
	user = mysql.fetch(user_query)
	if user and bcrypt.check_password_hash(user[0]['password'], password):
			session['id'] = user[0]['id']
			session['first_name'] = user[0]['first_name']
			return redirect(url_for('show'))
	flash('Invalid email or password', 'danger')
	return redirect(url_for('signin'))

@app.route('/signout')
def signout():
	session.pop('id')
	session.pop('first_name')
	return redirect(url_for('index'))

@app.route('/messages', methods=['GET', 'POST'])
def show():
	if request.method == 'GET':
		# fetch_messages_query = "SELECT messages.id as message_id, messages.message, concat(users.first_name, ' ', users.last_name) as author_name, messages.created_at FROM messages LEFT JOIN users ON users.id = messages.user_id order by created_at desc"
		fetch_messages_query = "SELECT messages.id AS message_id, messages.message, CONCAT(users.first_name, ' ', users.last_name) AS author_name, messages.created_at, GROUP_CONCAT(comments.comment SEPARATOR '-----') AS comments, GROUP_CONCAT(CONCAT(users2.first_name, ' ', users2.last_name) SEPARATOR '-----') AS comment_author, GROUP_CONCAT(comments.created_at SEPARATOR '-----') AS comment_created_at FROM messages LEFT JOIN users ON users.id = messages.user_id LEFT JOIN comments ON messages.id = comments.message_id LEFT JOIN users AS users2 ON users2.id = comments.user_id GROUP BY messages.id ORDER BY created_at DESC"
		all_messages = mysql.fetch(fetch_messages_query)
		for msg in all_messages:
			print '============'
			print msg
			print '============'
			msg['comments'] = str(msg['comments']).split('-----')
			msg['comment_author'] = str(msg['comment_author']).split('-----')
			msg['comment_created_at'] = str(msg['comment_created_at']).split('-----')
		print all_messages
		return render_template('messages.html', all_messages=all_messages)
	new_message = request.form['message']
	escaped_new_message = new_message.replace("'", "\\'")
	insert_message_query = "INSERT INTO messages (user_id, message, created_at, updated_at) VALUES ('{}', '{}', NOW(), NOW())".format(session['id'], escaped_new_message)
	print insert_message_query
	mysql.run_mysql_query(insert_message_query)
	return redirect(url_for('show'))

@app.route('/comments', methods=['POST'])
def create_comment():
	new_comment = request.form['comment']
	message_id = request.form['message_id']
	escaped_new_comment = new_comment.replace("'", "\\'")
	insert_comment_query = "INSERT INTO comments (message_id, user_id, comment, created_at, updated_at) VALUES ('{}', '{}', '{}', NOW(), NOW())".format(message_id, session['id'], escaped_new_comment)
	print insert_comment_query
	mysql.run_mysql_query(insert_comment_query)
	return redirect(url_for('show'))


app.run(debug=True)