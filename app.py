from flask import Flask  # импорт класса Flask из библиотеки flask (pip install flask)
from flask import render_template  # подключаем биб-ку для подключения html-шаблонов
from flask import request  # добавляем библиотеку request для обработки запросов
from flask import redirect  # redirect для переадресации
from flask import session  # для работы с сессиями
from flask import url_for  # для работы с относительным адресом
from pymongo import MongoClient  # для работы с MongoDB (pip install pymongo)
from bson.objectid import ObjectId  # для работы с _id в MongoDB
# from bcrypt import hashpw, gensalt
import bcrypt  # для шифрования паролей
import os
import pathlib
import requests
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token


app = Flask(__name__)  # создание объекта класса Flask (основным файлом будет сам этот файл (директива __name__))
app.secret_key = "testing"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "56547007955-m9mfjmd9tlf5d6ooseovhiadrlpk2uo6.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

client = MongoClient('localhost', 27017)  # создаем объект client класса MongoClient
db = client['pymongo_test']  # запускаем mongod.exe и работаем с БД 'pymongo_test'
collection = db['docs']  # работаем с коллекцией 'docs'
user_coll = db['users']  # с авторизацией работаем с коллекцией 'users'


@app.route('/', methods=['post', 'get'])  # функция-декоратор отслеживания главной страницы по URL-адресу ('/')
@app.route('/home', methods=['post', 'get'])  # обработка двух URL-адресов
def index():
    message = ''
    return render_template("index.html", message=message)  # вывод шаблона на экран


@app.route("/login_google")
def login_google():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        return redirect(url_for("login"))

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["email"] = id_info.get("email")
    email = session["email"]
    # return render_template('logged_in.html', email=email)
    return redirect(url_for("logged_in"))


@app.route('/register', methods=['post', 'get'])
def register():
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        user = request.form.get("user")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        if not user or not email or not password1 or not password2:
            message = 'All fields must be filled in! '
            return render_template('register.html', message=message)

        user_found = user_coll.find_one({"user": user})
        email_found = user_coll.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('register.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('register.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('register.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'user': user, 'email': email, 'password': hashed}
            user_coll.insert_one(user_input)

            user_data = user_coll.find_one({"email": email})
            new_email = user_data['email']

            # return render_template('logged_in.html', email=new_email)
            return redirect(url_for("login"))
    message = ''
    return render_template("register.html", message=message)


@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        return render_template('logged_in.html', email=email)
    else:
        return redirect(url_for("login"))


@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            message = 'All fields must be filled in! '
            return render_template('login.html', message=message)

        email_found = user_coll.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            password_check = email_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), password_check):
                session["email"] = email_val
                return redirect(url_for('logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        # session.pop("email", None)
        session.clear()
        return render_template("logout.html")
    else:
        return render_template('index.html')


@app.route('/docs')  # все документы на сайте
def docs():
    results = collection.find()  # создаем объект, кот. обращается к коллекции
    docs_col = [result for result in results]  # создаем список документов из коллекции
    print(docs_col)  # выводим список в консоль
    return render_template("docs.html", docs_col=docs_col)  # передаем список в шаблон (доступ по имени docs)


@app.route('/docs/<_id>/delete')  # удаление документа
def delete(_id):
    if "email" not in session:  # если не вошел в систему, доступа нет
        return redirect(url_for("login"))   # нужно войти в систему

    id_ = ObjectId(_id)  # для корректного доступа к _id документа

    try:
        collection.delete_one({'_id': id_})
        print('Document with _id: ' + _id + ' has been deleted successfully.')
        # удаляем документ с заданным _id в коллекцию
        # и выводим в консоль его _id
        return redirect('/docs')  # переадресовываем на вывод коллекции документов
    except:
        print('An error occurred while deleting the document')
        return 'An error occurred while deleting the document'


@app.route('/docs/<_id>/update', methods=['POST', 'GET'])  # редактирование документа
def update_doc(_id):
    if "email" not in session:  # если не вошел в систему, доступа нет
        return redirect(url_for("login"))   # нужно войти в систему

    id_ = ObjectId(_id)  # для корректного доступа к _id документа
    doc = collection.find_one({'_id': id_})  # находим документ с заденным _id
    print(doc)
    if request.method == 'POST':
        title = request.form['title']  # присваиваем переменным значения из формы
        author = request.form['author']
        year = request.form['year']

        updating_doc = {  # создаем новый документ
            "title": title,
            "author": author,
            "year": year
        }

        try:
            collection.update_one({'_id': id_}, {'$set': updating_doc})
            print('Document with _id: ' + str(id_) + ' has been updated successfully.')
            # изменяем значение полей документа в коллекции
            # и выводим в консоль его _id
            return redirect('/docs')  # переадресовываем на вывод коллекции документов
        except:
            print('An error occurred while updating the document.')
            return 'An error occurred while updating the document.'
    else:
        return render_template("update_doc.html", doc=doc)  # передать документ в шаблон


@app.route('/create_doc', methods=['POST', 'GET'])  # создание документа
# добавляем метод POST обработки запоса (по умолчанию только GET)
def create_doc():
    if "email" not in session:  # если не вошел в систему, доступа нет
        return redirect(url_for("login"))   # нужно войти в систему

    if request.method == 'POST':
        title = request.form['title']  # присваиваем переменным значения из формы
        author = request.form['author']
        year = request.form['year']

        new_doc = {  # создаем новый документ
            "title": title,
            "author": author,
            "year": year
        }

        try:
            result = collection.insert_one(new_doc).inserted_id
            print('Document with _id: ' + str(result) + ' has been created successfully.')
            # добавляем новый документ в коллекцию
            # и выводим в консоль его _id
            return redirect('/docs')  # переадресовываем на вывод коллекции документов
        except:
            print('An error occurred while creating the document.')
            return 'An error occurred while creating the document.'
    else:
        return render_template("create_doc.html")  # будет обрабатывать как данные из формы,
        # так и прямой заход на страницу


if __name__ == "__main__":  # если программа запускается через этот файл
    app.run(debug=True)  # запуск локального сервера в режиме отладки (вывод инф-ции об ошибках)
