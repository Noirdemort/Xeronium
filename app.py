from flask import Flask, request, render_template, session
import pymongo
import random
import string
import os
import re
from hashlib import sha512
mongo_url = 'mongodb+srv://cimmerian: TivmprRd7spxx3pG@xenophyte-gpkbv.azure.mongodb.net/test?retryWrites=true&w=majority'

client = pymongo.MongoClient(mongo_url)
xenotron = client['xenotron']
users = xenotron['users']

app = Flask(__name__)
app.secret_key = 'HJDSKJSK_SCBJHSIUHSC_WDNJSNS_@IUSDJHA_SDBWOSXSXJKWXZMCVGHBNHU=12E09DE129398ZMMLALAPRFE'


def gen_hash(string, salt):
    return sha512((salt+string).encode()).hexdigest()


def salt():
    return ''.join(random.SystemRandom().choice(
        string.ascii_uppercase + string.digits) for _ in range(50))


def checkFields(form, conditions):
    for con in conditions:
        if not con in form:
            return False
    return True


@app.route('/', methods=["GET"])
def showLogin():
    return render_template('index.html', username="user", res=[], logged_in=False)


@app.route('/register', methods=['GET', "POST"])
def registerToHome():
    if request.method == 'GET':
        return render_template('register.html')
    credentials = dict(request.form)
    if not checkFields(credentials, ['username', 'name', 'password', 'public_key', 'confirm_password']):
        return "Insufficient fields!"
    credentials['username'] = credentials['username'].lower()
    if users.find_one({"username": credentials['username']}):
        return "User already exists!"
    password = credentials['password']
    confirm_password = credentials['confirm_password']
    if password != confirm_password:
        return "passwords don't match"
    sal = salt()
    link = gen_hash(credentials['username'], sal)[:7]
    while users.find_one({'link': link}):
        link = gen_hash(credentials['username'], salt())[:7]
    user = {"username": credentials['username'], 'name': credentials['name'], "password": gen_hash(
        credentials['password'], sal), "public_key": credentials['public_key'], "salt": sal, 'link': link}
    users.insert_one(user)
    return render_template('login.html')


@app.route('/login', methods=['GET', "POST"])
def loginToHome():
    if request.method == "GET":
        return render_template('login.html')
    credentials = dict(request.form)
    if not checkFields(credentials, ['password', 'username']):
        return "Insufficient fields!"
    password = credentials['password']
    user = users.find_one({"username": credentials['username'].lower()})

    if user is None:
        return "No such account"
    if gen_hash(password, user['salt']) != user['password']:
        return "Invalid Credentials"
    session['username'] = credentials['username'].lower()
    return render_template('index.html', username=credentials['username'], res=[], logged_in=True)


@app.route('/fetch/<link>')
def getPublicKey(link):
    user = users.find_one({'link': link})
    if user is None:
        return "No such user"
    return user['public_key']


@app.route('/change', methods=['POST'])
def changeKey():
    if 'username' not in session:
        return render_template('login.html')
    data = dict(request.form)
    if not checkFields(data, ['public_key']):
        return 'Insufficient fields!'
    users.update_one({"username": session['username']}, {
                     '$set': {
                         "public_key": data['public_key']
                     }
                     })
    return render_template('index.html', username=session['username'], res=[], logged_in=True)


@app.route('/search', methods=['GET', 'POST'])
def searchUser():
    if request.method == "GET":
        if 'username' in session:
            user = session['username']
            logged_in = True
        else:
            user = 'user'
            logged_in = False
        return render_template('index.html', username=user, res=[], logged_in=logged_in)
    elif request.method == "POST":
        data = dict(request.form)
        print(data)
        word = data["search"].lower()
        search_expr = re.compile(f".*{word}.*", re.I)
        search_request = {
            '$or': [
                {'username': {'$regex': search_expr}},
                {'name': {'$regex': search_expr}},
            ]
        }
        results = list(users.find(search_request))
        mod_results = []
        for result in results:
            mod_results.append(
                [result['username'], result['name'], result['link']])
        if 'username' in session:
            user = session['username']
            logged_in = True
        else:
            user = 'user'
            logged_in = False
        return render_template('index.html', username=user, res=mod_results, logged_in=logged_in)
    else:
        return 'Unsupported Method!'


@app.route('/logout')
def logout():
    del session['username']
    return render_template('login.html')


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
