import os

import flask
from authlib.client import OAuth2Session
from time import sleep
from .auth import Auth

COOKIE_EXPIRY = 60 * 60 * 24 * 14
COOKIE_AUTH_USER_NAME = 'AUTH-USER'
COOKIE_AUTH_USER_EMAIL = 'AUTH-EMAIL'
COOKIE_AUTH_ACCESS_TOKEN = 'AUTH-TOKEN'

AUTH_STATE_KEY = 'auth_state'

CLIENT_ID = os.environ.get('GOOGLE_AUTH_CLIENT_ID')
CLIENT_SECRET = os.environ.get('GOOGLE_AUTH_CLIENT_SECRET')
AUTH_REDIRECT_URI = os.environ.get('GOOGLE_AUTH_REDIRECT_URI')


class GoogleAuth(Auth):
    """
    Google OAuth2 authentication for Dash apps
    to initialize your Dash app with Google OAuth2 authentication, use this class as follows:
    ```python
    from dash import Dash
    from dash_google_oauth import GoogleAuth

    app = Dash(__name__)
    auth = GoogleAuth(app, allowed_emails=['example.com'])
    ```
    to use this class, you need to set the following environment variables:
    - GOOGLE_AUTH_CLIENT_ID: Google OAuth2 client ID
    - GOOGLE_AUTH_CLIENT_SECRET: Google OAuth2 client secret
    - GOOGLE_AUTH_SCOPE: Google OAuth2 scope
    - GOOGLE_AUTH_URL: Google OAuth2 authorization URL
    - GOOGLE_AUTH_TOKEN_URI: Google OAuth2 token URL
    - GOOGLE_AUTH_USER_INFO_URL: Google OAuth2 user info URL
    - GOOGLE_AUTH_REDIRECT_URI: Redirect URI for Google OAuth2
    - FLASK_SECRET_KEY: Flask secret key
    """
    def __init__(self, app, allowed_emails=None):
        """
        :param app: Dash app
        :param allowed_emails: List of allowed email domains
        """
        Auth.__init__(self, app)
        self.allowed_emails = allowed_emails
        app.server.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
        app.server.config['SESSION_TYPE'] = 'filesystem'

        @app.server.route('/login/callback')
        def callback():
            if not self.is_authorized():
                return self.login_callback()
            return flask.redirect('/')


        @app.server.route('/logout')
        def logout():
            return self.logout()

    def is_authorized(self):
        user = flask.request.cookies.get(COOKIE_AUTH_USER_NAME)
        token = flask.request.cookies.get(COOKIE_AUTH_ACCESS_TOKEN)
        email = flask.request.cookies.get(COOKIE_AUTH_USER_EMAIL)
        if not user or not token or not email:
            return False
        return flask.session.get(user) == token

    def login_request(self):
        session = OAuth2Session(
            CLIENT_ID,
            CLIENT_SECRET,
            scope=os.environ.get('GOOGLE_AUTH_SCOPE'),
            redirect_uri=AUTH_REDIRECT_URI
        )

        uri, state = session.create_authorization_url(os.environ.get('GOOGLE_AUTH_URL'))
        

        flask.session['REDIRECT_URL'] = flask.request.url
        flask.session[AUTH_STATE_KEY] = state
        flask.session.permanent = True
        return flask.redirect(uri, code=302)

    def auth_wrapper(self, f):
        def wrap(*args, **kwargs):
            if not self.is_authorized():
                return flask.redirect('/login/callback')

            response = f(*args, **kwargs)
            return response

        return wrap

    def index_auth_wrapper(self, original_index):
        def wrap(*args, **kwargs):
            if self.is_authorized():
                return original_index(*args, **kwargs)
            else:
                return flask.redirect('/login/callback')

        return wrap

    def login_callback(self):
        if 'error' in flask.request.args:
            if flask.request.args.get('error') == 'access_denied':
                return 'You denied access.'
            return 'Error encountered.'

        if 'code' not in flask.request.args and 'state' not in flask.request.args:
            return self.login_request()
        else:
            # user is successfully authenticated
            google = self.__get_google_auth(state=flask.request.args['state'])
            try:
                token = google.fetch_token(
                    os.environ.get('GOOGLE_AUTH_TOKEN_URI'),
                    client_secret=CLIENT_SECRET,
                    authorization_response=flask.request.url
                )
            except Exception as e:
                return self.login_request()

            google = self.__get_google_auth(token=token)
            resp = google.get(os.environ.get('GOOGLE_AUTH_USER_INFO_URL'))
            if resp.status_code == 200:
                user_data = resp.json()
                email_dom = user_data["email"].split('@')[1]
                if self.allowed_emails and email_dom not in self.allowed_emails:
                    return 'You are not allowed to access this application.'
                r = flask.redirect(flask.session.get('REDIRECT_URL', '/'))
                r.set_cookie(COOKIE_AUTH_USER_NAME, user_data['name'], max_age=COOKIE_EXPIRY)
                r.set_cookie(COOKIE_AUTH_USER_EMAIL, user_data['email'], max_age=COOKIE_EXPIRY)
                r.set_cookie(COOKIE_AUTH_ACCESS_TOKEN, token['access_token'], max_age=COOKIE_EXPIRY)
                flask.session[user_data['name']] = token['access_token']
                return r
            return 'Could not fetch your information.'

    @staticmethod
    def __get_google_auth(state=None, token=None):
        if token:
            return OAuth2Session(CLIENT_ID, token=token)
        if state:
            return OAuth2Session(
                CLIENT_ID,
                state=state,
                redirect_uri=AUTH_REDIRECT_URI
            )
        return OAuth2Session(
            CLIENT_ID,
            redirect_uri=AUTH_REDIRECT_URI,
        )

    @staticmethod
    def logout():
        r = flask.redirect('/')
        r.delete_cookie(COOKIE_AUTH_USER_NAME)
        r.delete_cookie(COOKIE_AUTH_ACCESS_TOKEN)
        r.delete_cookie(COOKIE_AUTH_USER_EMAIL)
        return r