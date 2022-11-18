from flask import Flask, render_template, request
import ibm_db
import json
import os
import csv
import pathlib
import requests
import tweepy
import google.auth.transport.requests
from flask_mail import Mail, Message
from random import randint
from flask import Flask, session, abort, redirect
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol

connectionstring = "DATABASE=bludb;HOSTNAME=ea286ace-86c7-4d5b-8580-3fba46b1c66.bs2io90l08kqb1od8lcg.databases.appdomain.cloud;PORT=31505;PROTOCOL=TCPIP;UID=jrz00477;PWD=2e1ORUoHykD7rc3l;SECURITY=SSL;"
connection = ibm_db.connect(connectionstring, '', '')

app = Flask(__name__)
app.secret_key = "HireMe.com"

mail = Mail(app)
app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = 'slakshman64@gmail.com'
app.config['MAIL_PASSWORD'] = 'ybxjidlujafaak'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

first_name = ""
last_name = ""
password = ""

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

otp = randint(000000, 999999)
first_name = ""
last_name = ""
useremail = ""
password = ""

consumer_key = ''
consumer_secret = ''
tcallback = 'http://127.0.0.1:5000/tcallback'

GOOGLE_CLIENT_ID = ""
client_secrets_file = os.path.join(
    pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

@app.route("/signup")
@app.route("/")
def signup():
    return render_template("signup.html")


@app.route('/verification', methods=["POST", "GET"])
def verify():
    global first_name
    global last_name
    global useremail
    global password
    global otp
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password = request.form.get('password')
        useremail = request.form.get('email')
        sql = "SELECT * FROM User WHERE email =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, useremail)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)

        if (account):
            return render_template('signup.html', msg="You are already a member, please login using your details")
        else:
            session['regmail'] = useremail
            otp = randint(000000, 999999)
            msg = Message(subject='OTP', sender='slakshman664@gmail.com',
                          recipients=[session['regmail']])
            msg.body = "You have succesfully registered for Hire Me!\nUse the OTP given below to verify your email ID.\n\t\t" + \
                str(otp)
            mail.send(msg)
            return render_template('verification.html')

    elif ("regmail" in session):
        if request.method == 'GET':
            otp = randint(000000, 999999)
            msg = Message(subject='OTP', sender='slakshman664@gmail.com',
                          recipients=[session['regmail']])
            msg.body = "You have succesfully registered for Hire Me!\nUse the OTP given below to verify your email ID.\n\t\t" + \
                str(otp)
            mail.send(msg)
            return render_template('verification.html', resendmsg="OTP has been resent")
    else:
        return redirect('/')


@app.route('/validate', methods=['POST', 'GET'])
def validate():
    if ('regmail' in session):
        global first_name
        global last_name
        global useremail
        global password
        user_otp = request.form['otp']
        if otp == int(user_otp):
            insert_sql = "INSERT INTO Usr(userid,first_name,last_name,email,pass,newuser) VALUES (?,?,?,?,?,?)"
            prep_stmt = ibm_db.prepare(connection, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, int((hash(first_name) % 8999) + 1001))
            ibm_db.bind_param(prep_stmt, 2, first_name)
            ibm_db.bind_param(prep_stmt, 3, last_name)
            ibm_db.bind_param(prep_stmt, 4, useremail)
            ibm_db.bind_param(prep_stmt, 5, password)
            ibm_db.bind_param(prep_stmt, 6, True)
            ibm_db.execute(prep_stmt)
            return render_template('signin.html')
        else:
            return render_template('verification.html', msg="OTP is invalid. Please enter a valid OTP")
    else:
        return redirect('/')

@app.route("/googlelogin")
def googlelogin():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.request.Request(
        session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["email_id"] = id_info.get("email")
    session["first_name"] = id_info.get("given_name")
    session["last_name"] = id_info.get("family_name")

    global first_name
    global last_name
    global useremail
    global password

    first_name = session['first_name']
    last_name = session['last_name']
    useremail = session['email_id']
    password = ""

    sql = "SELECT * FROM User WHERE email =?"
    stmt = ibm_db.prepare(connection, sql)
    ibm_db.bind_param(stmt, 1, useremail)
    ibm_db.execute(stmt)
    account = ibm_db.fetch_assoc(stmt)

    if account:
        if (account['NEWUSER'] == 1):
            return redirect('/profile')
        return redirect('/home')

    else:
        insert_sql = "INSERT INTO User(userid,first_name,last_name,email,pass,newuser) VALUES (?,?,?,?,?)"
        prep_stmt = ibm_db.prepare(connection, insert_sql)
        ibm_db.bind_param(prep_stmt, 1, int((hash(first_name) % 8999) + 1001))
        ibm_db.bind_param(prep_stmt, 2, first_name)
        ibm_db.bind_param(prep_stmt, 3, last_name)
        ibm_db.bind_param(prep_stmt, 4, useremail)
        ibm_db.bind_param(prep_stmt, 5, password)
        ibm_db.bind_param(prep_stmt, 6, True)
        ibm_db.execute(prep_stmt)
        return redirect("/profile")

@app.route('/tlogin')
def auth():
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret, tcallback)
    url = auth.get_authorization_url()
    session['request_token'] = auth.request_token
    return redirect(url)

@app.route('/tcallback')
def twitter_callback():

    global first_name
    request_token = session['request_token']
    print(request_token)
    del session['request_token']

    auth = tweepy.OAuthHandler(consumer_key, consumer_secret, tcallback)
    auth.request_token = request_token
    verifier = request.args.get('oauth_verifier')
    auth.get_access_token(verifier)
    session['token'] = (auth.access_token, auth.access_token_secret)
    first_name = session['token']
    return redirect('/profile')

@app.route("/logout")
def logout():
    session.pop('useremail', None)
    session.pop('regmail', None)
    session.pop('newuser', None)
    session.pop('role',None)
    return redirect("/login")

@app.route("/home", methods=['POST', 'GET'])
def home():
    if "useremail" in session:
        if request.method == 'POST':
            user_search = request.form.get('search')
            arr = []
            with open("Company_Database.csv", 'r') as file:
                csvreader = csv.reader(file)
                for i in csvreader:
                    if i[2].casefold() == user_search.casefold():
                        dict = {
                            'jobid': i[0], 'cname': i[1], 'role': i[2], 'ex': i[3], 'skill': i[4], 'vacancy': i[5], 'stream': i[6], 'job_location': i[7], 'salary': i[8], 'link': i[9], 'logo': i[10]
                        }
                        arr.append(dict)
            companies = json.dumps(arr)

            return render_template("index.html", companies=companies)
        else:
            sql = "SELECT * FROM appliedcompany WHERE userid =?"
            stmt = ibm_db.prepare(connection, sql)
            ibm_db.bind_param(stmt, 1, session['userid'])
            ibm_db.execute(stmt)
            account = ibm_db.fetch_assoc(stmt)
            arr = []
            with open("Company_Database.csv", 'r') as file:
                csvreader = csv.reader(file)
                for i in csvreader:
                    if i[2].casefold() == session['role'].casefold():
                        dict = {
                            'jobid': i[0], 'cname': i[1], 'role': i[2], 'ex': i[3], 'skill': i[4], 'vacancy': i[5], 'stream': i[6], 'job_location': i[7], 'salary': i[8], 'link': i[9], 'logo': i[10]
                        }
                        arr.append(dict)
            companies = json.dumps(arr)
            return render_template("index.html", companies=companies)
    else:
        return redirect('/login')

@app.route('/like', methods=['POST', 'GET'])
def store_like():
    session['jobid'] = request.form.get('jobid')
    print(session['jobid'])
    insert_sql = "INSERT INTO LIKES(USERID,JOBID) VALUES(?,?)"
    prep_stmt = ibm_db.prepare(connection, insert_sql)
    ibm_db.bind_param(prep_stmt, 1, session['userid'])
    ibm_db.bind_param(prep_stmt, 2, session['jobid'])
    ibm_db.execute(prep_stmt)
    return None


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        useremail = request.form.get('email')
        password = request.form.get('password')
        sql = "SELECT * FROM user WHERE email =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, useremail)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        print(account)
        if account:
            session["useremail"] = useremail
            session["newuser"] = account['NEWUSER']
            if (password == str(account['PASS']).strip()):
                session['userid'] = account['USERID']
                if (session['newuser'] == 1):
                    return redirect('/profile')
                else:
                    sql = "SELECT * FROM profile WHERE email_id =?"
                    stmt = ibm_db.prepare(connection, sql)
                    ibm_db.bind_param(stmt, 1, useremail)
                    print(useremail)
                    ibm_db.execute(stmt)
                    account = ibm_db.fetch_assoc(stmt)
                    session['role'] = account['SKILL']
                    return redirect('/home')
            else:
                return render_template('signin.html', msg="Password is invalid")
        else:
            return render_template('signin.html', msg="Email is invalid")
    else:
        if "useremail" in session:
            return redirect('/home')
        else:
            return render_template('signin.html')

@app.route("/profile", methods=["POST", "GET"])
def profile():
    if "useremail" in session:
        if (session['newuser'] == 1 and request.method == 'POST'):
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            mobile_no = request.form.get('mobile_no')
            address_line_1 = request.form.get('address_line_1')
            address_line_2 = request.form.get('address_line_2')
            zipcode = request.form.get('zipcode')
            city = request.form.get('city')
            education = request.form.get('education')
            country = request.form.get('countries')
            state = request.form.get('states')
            experience = request.form.get('experience')
            job_title = request.form.get('job_title')

            insert_sql = "INSERT INTO profile VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"

            prep_stmt = ibm_db.prepare(connection, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, first_name)
            ibm_db.bind_param(prep_stmt, 2, last_name)
            ibm_db.bind_param(prep_stmt, 3, mobile_no)
            ibm_db.bind_param(prep_stmt, 4, address_line_1)
            ibm_db.bind_param(prep_stmt, 5, address_line_2)
            ibm_db.bind_param(prep_stmt, 6, zipcode)
            ibm_db.bind_param(prep_stmt, 7, city)
            ibm_db.bind_param(prep_stmt, 8, session['useremail'])
            ibm_db.bind_param(prep_stmt, 9, education)
            ibm_db.bind_param(prep_stmt, 10, country)
            ibm_db.bind_param(prep_stmt, 11, state)
            ibm_db.bind_param(prep_stmt, 12, experience)
            ibm_db.bind_param(prep_stmt, 13, job_title)
            ibm_db.execute(prep_stmt)

            insert_sql = "UPDATE USER SET newuser = false WHERE email=?"
            session['newuser'] = 0
            prep_stmt = ibm_db.prepare(connection, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, session['useremail'])
            ibm_db.execute(prep_stmt)
            session['role'] = job_title
            return redirect('/home')

        elif (session['newuser'] == 0 and request.method == "GET"):
            sql = "SELECT * FROM profile WHERE email_id =?"
            stmt = ibm_db.prepare(connection, sql)
            ibm_db.bind_param(stmt, 1, session['useremail'])
            ibm_db.execute(stmt)
            account = ibm_db.fetch_assoc(stmt)
            first_name = account['FIRST_NAME']
            last_name = account['LAST_NAME']
            mobile_no = account['MOBILE_NUMBER']
            address_line_1 = account['ADDRESS_LINE_1']
            address_line_2 = account['ADDRESS_LINE_2']
            zipcode = account['ZIPCODE']
            education = account['EDUCATION']
            countries = account['COUNTRY']
            states = account['STATE']
            city = account['CITY']
            experience = account['EXPERIENCE']
            job_title = account['SKILL']
            return render_template('profile.html', email=session['useremail'], newuser=session['newuser'], first_name=first_name, last_name=last_name, address_line_1=address_line_1, address_line_2=address_line_2, zipcode=zipcode, education=education, countries=countries, states=states, experience=experience, job_title=job_title, mobile_no=mobile_no, city=city)

        elif (session['newuser'] == 0 and request.method == "POST"):
            mobile_no = request.form.get('mobile_no')
            address_line_1 = request.form.get('address_line_1')
            address_line_2 = request.form.get('address_line_2')
            zipcode = request.form.get('zipcode')
            city = request.form.get('city')
            country = request.form.get('countries')
            state = request.form.get('states')
            experience = request.form.get('experience')
            job_title = request.form.get('job_title')
            sql = "UPDATE profile SET(mobile_number,address_line_1,address_line_2,zipcode,city,country,state,experience,skill)=(?,?,?,?,?,?,?,?,?) where email_id =?"
            stmt = ibm_db.prepare(connection, sql)
            ibm_db.bind_param(stmt, 1, mobile_no)
            ibm_db.bind_param(stmt, 2, address_line_1)
            ibm_db.bind_param(stmt, 3, address_line_2)
            ibm_db.bind_param(stmt, 4, zipcode)
            ibm_db.bind_param(stmt, 5, city)
            ibm_db.bind_param(stmt, 6, country)
            ibm_db.bind_param(stmt, 7, state)
            ibm_db.bind_param(stmt, 8, experience)
            ibm_db.bind_param(stmt, 9, job_title)
            ibm_db.bind_param(stmt, 10, session['useremail'])
            ibm_db.execute(stmt)
            session['role'] = job_title
            return redirect("/home")
        else:
            return render_template('profile.html', newuser=session['newuser'], email=session['useremail'])
    else:
        return redirect("/login")

@app.route("/forgotpass", methods=["POST", "GET"])
def forgotpass():
    global i
    global otp
    global email

    if request.method == 'POST':

        useremail = request.form.get('email')
        user_otp = request.form.get('OTP')
        password = request.form.get('password')

        sql = "SELECT * FROM User WHERE email =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, useremail)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)

        if i == 1:
            if otp == int(user_otp):
                i = 2
                return render_template('forgotpass.html', i=i)
            else:
                return render_template('forgotpass.html', msg="OTP is invalid. Please enter a valid OTP", i=i)

        elif i == 2:
            sql = "UPDATE USER SET pass=? WHERE email=?"
            stmt = ibm_db.prepare(connection, sql)
            ibm_db.bind_param(stmt, 1, password)
            ibm_db.bind_param(stmt, 2, email)
            ibm_db.execute(stmt)
            i = 1
            return render_template('signin.html')

        elif i == 0:
            if (account):
                otp = randint(000000, 999999)
                email = request.form['email']
                msg = Message(subject='OTP', sender='slakshman664@gmail.com',
                              recipients=[email])
                msg.body = "Forgot your password?\n\nWe received a request to reset the password for your account.Use the OTP given below to reset the password.\n\n" + \
                    str(otp)
                mail.send(msg)
                i = 1
                return render_template('forgotpass.html', i=i)
            else:
                return render_template('forgotpass.html', msg="It looks like you are not yet our member!")
    i = 0
    return render_template('forgotpass.html')

@app.route("/apply/<string:jobid>", methods=["POST", "GET"])
def apply():
    if "useremail" in session:
        session['appliedjobid'] = int(json.loads(jobid))
        stmt = ibm_db.prepare(
            connection, "select * from appliedcompany where userid=?")
        ibm_db.bind_param(stmt, 1, session['userid'])
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        while (account != False):
            print(session['appliedjobid'])
            if (session['appliedjobid'] == int(account["JOBID"])):
                return render_template('index.html', msg="You have already applied for this job!"), {"Refresh": "3; url=/home"}
            account = ibm_db.fetch_assoc(stmt)

        sql = "SELECT * FROM profile WHERE email_id =?"
        stmt = ibm_db.prepare(connection, sql)
        ibm_db.bind_param(stmt, 1, session['useremail'])
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)
        first_name = account['FIRST_NAME']
        last_name = account['LAST_NAME']
        mobile_no = account['MOBILE_NUMBER']
        zipcode = account['ZIPCODE']
        education = account['EDUCATION']
        countries = account['COUNTRY']
        states = account['STATE']
        city = account['CITY']
        experience = account['EXPERIENCE']
        job_title = account['SKILL']
        return render_template('apply.html', email=session['useremail'], first_name=first_name, last_name=last_name, zipcode=zipcode, education=education, countries=countries, states=states, experience=experience, mobile_no=mobile_no, city=city, job_title=job_title)

    else:
        return redirect('/login')

@app.route("/applysuccess", methods=["POST", 'GET'])
def applysuccess():
    if "useremail" in session:
        if request.method == "POST":
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            mobile_no = request.form.get('mobile_no')
            zipcode = request.form.get('zipcode')
            city = request.form.get('city')
            education = request.form.get('education')
            country = request.form.get('countries')
            state = request.form.get('states')
            experience = request.form.get('experience')
            insert_sql = "INSERT INTO appliedcompany(userid,jobid,first_name,last_name,mobile_number,zipcode,city,email,education,country,state,experience) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            prep_stmt = ibm_db.prepare(connection, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, session['userid'])
            ibm_db.bind_param(prep_stmt, 2, session['appliedjobid'])
            ibm_db.bind_param(prep_stmt, 3, first_name)
            ibm_db.bind_param(prep_stmt, 4, last_name)
            ibm_db.bind_param(prep_stmt, 5, mobile_no)
            ibm_db.bind_param(prep_stmt, 6, zipcode)
            ibm_db.bind_param(prep_stmt, 7, city)
            ibm_db.bind_param(prep_stmt, 8, session['useremail'])
            ibm_db.bind_param(prep_stmt, 9, education)
            ibm_db.bind_param(prep_stmt, 10, country)
            ibm_db.bind_param(prep_stmt, 11, state)
            ibm_db.bind_param(prep_stmt, 12, experience)

            ibm_db.execute(prep_stmt)
            return redirect('/applysuccess')
        else:
            return render_template('applysuccess.html'), {"Refresh": "5; url=/home"}

    else:
        return redirect('/home')
