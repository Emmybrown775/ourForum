from datetime import datetime
import os
from flask import Flask, render_template, flash, request, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, UserMixin, LoginManager, login_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Float
import africastalking


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['SECRET_KEY'] = os.environ.get('SECRET-KEY')
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

africastalking.initialize(
    username='sandbox',
    api_key=os.environ.get('API-KEY'),
)

sms = africastalking.SMS
SHORT_CODE = "3423"

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)
    is_online = db.Column(db.Boolean, nullable=False, default=True)
    questions = db.relationship('Question', back_populates='author')
    comments = db.relationship('Comment', back_populates='author')


class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(255), nullable=True)
    title = db.Column(db.String, nullable=False)
    question = db.Column(db.String, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', back_populates='questions')
    comments = db.relationship('Comment', back_populates='question')
    post_time = db.Column(db.DateTime, default=datetime.utcnow())


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship('User', back_populates='comments')
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'))
    question = db.relationship('Question', back_populates='comments')
    comment = db.Column(db.String, nullable=False)
    comment_time = db.Column(db.DateTime, default=datetime.utcnow())


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():  # put application's code here
    if request.method == 'POST':
        phone_number = f"+234{request.form['phoneNumber']}"
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        username = request.form['userName']

        is_phone = db.session.execute(db.select(User).where(User.phone_number == phone_number)).scalar()
        is_username = db.session.execute(db.select(User).where(User.username == username)).scalar()

        if is_phone:
            # User already exists
            flash("Phone Number already exists")
            return redirect(url_for('sign_up'))
        elif is_username:
            flash("Username already exists")
            return redirect(url_for('sign_up'))
        if password == "" or phone_number == "" or confirm_password == "":
            flash('Password and phone number cannot be empty!')
            return redirect(url_for("sign_up"))
        else:
            if password != confirm_password:
                flash('Passwords do not match')
                return redirect(url_for("sign_up"))
            else:

                hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

                if phone_number[0] == "0":
                    phone_number = phone_number[1:]

                new_user = User(
                    phone_number=phone_number,
                    password=hashed_password,
                    username=username
                )
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)

                return redirect(url_for("home"))
    else:
        return render_template("signup.html")


@app.route("/ask-question", methods=['GET', 'POST'])
@login_required
def ask_question():
    if request.method == 'POST':
        print(request.form.to_dict())
        category = request.form.get('category')
        print(category)
        title = request.form['title']
        question = request.form['question']
        author = current_user

        if category == "" or title == "" or question == "" or author == "":
            flash('All fields are required!')
            return redirect(url_for("ask_question"))
        else:
            new_question = Question(
                category=category,
                title=title,
                question=question,
                author=author
            )
            db.session.add(new_question)
            db.session.commit()
            return redirect(url_for("home"))

    return render_template("post-question.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("sign_up"))


@app.route("/")
def home():
    questions = db.session.execute(db.select(Question).order_by(Question.id)).scalars()
    return render_template("questions.html", questions=questions)

@app.route("/my-questions")
def my_questions():
    questions = current_user.questions
    return render_template("questions.html", questions=questions)


@app.route("/question/<int:question_id>", methods=['GET', 'POST'])
def question(question_id):
    current_question = db.get_or_404(Question, question_id)
    if request.method == 'POST':
        comment = request.form["suggestion"]
        new_comment = Comment(
            author=current_user,
            question=current_question,
            comment=comment
        )
        db.session.add(new_comment)
        db.session.commit()

        ## Sends Comment to SMS user via SMS
        if not current_question.author.is_online:
            message = f"(From: {current_user.username})\n{comment}"
            send_sms([current_question.author.phone_number], message, SHORT_CODE)

        return redirect(url_for("question", question_id=current_question.id))
    else:
        return render_template("open-question.html", question=current_question)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    else:
        if request.method == "POST":
            phone_number = request.form['phoneNumber']
            password = request.form['password']

            result = db.session.execute(db.select(User).where(User.phone_number == phone_number)).scalar()
            if result is not None:
                user = result
                if check_password_hash(user.password, password):
                    login_user(user)
                    return redirect(url_for("home"))
                else:
                    flash('Incorrect password!')
                    return redirect(url_for("login"))
            else:
                flash('Phone Number does not exist!')
                return redirect(url_for("login"))

        else:
            return render_template("login.html")


@app.route("/receive-sms", methods=['POST'])
def receive_sms():
    # Here the server waits for a call from Africa's Talking (The two-way sms provider i worked with) then gets the
    # message and phone number from the message sent to our shortcode. Then saves the question to the database, if the
    # user has already been registered or creates a new user and then posts the message if not.
    data = request.form.to_dict()
    phone_number = data["from"]
    text = data["text"]
    print(phone_number)
    result = db.session.execute(db.select(User).where(User.phone_number == phone_number)).scalar()
    if result is not None:
        user = result
        new_question = Question(
            title="A New Question",
            question=text,
            author=user

        )
        db.session.add(new_question)
        db.session.commit()
        return Response(status=200)
    else:
        new_user = User(
            phone_number=phone_number,
            is_online=False,
            username="Sent From SMS"
        )
        db.session.add(new_user)
        db.session.commit()

        result = db.session.execute(db.select(User).where(User.phone_number == phone_number)).scalar()
        user = result
        new_question = Question(
            title="A New Question",
            question=text,
            author=user

        )
        db.session.add(new_question)
        db.session.commit()

        return Response(status=200)


def send_sms(recipients, message, sender):
    try:
        response = sms.send(message, recipients, sender)
        print(response)
    except Exception as e:
        print(e)






if __name__ == '__main__':
    app.run(port=4000)
