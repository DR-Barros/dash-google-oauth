# Dash Google OAuth

This is a fork of the work by Hossein Jazayeri that implements a simple library using Google OAuth to authenticate and view a Dash app, 
based on [dash-auth](https://github.com/plotly/dash-auth). 
Upon authentication, a cookie is created and kept for 2 weeks.

### Setup
Navigate to [Google API Console](https://console.cloud.google.com/apis/credentials), and setup an OAuth credentials
with `/login/callback` as authorized redirect URL i.e. `http://localhost:5000/login/callback`.

Install the package:
```
$ pip install git+https://github.com/DR-Barros/dash-google-oauth.git
```
Define following environment variables:
```
FLASK_SECRET_KEY

GOOGLE_AUTH_URL
GOOGLE_AUTH_SCOPE
GOOGLE_AUTH_TOKEN_URI
GOOGLE_AUTH_REDIRECT_URI
GOOGLE_AUTH_USER_INFO_URL
GOOGLE_AUTH_CLIENT_ID
GOOGLE_AUTH_CLIENT_SECRET
```
for example using [python-dotenv](https://pypi.org/project/python-dotenv/):
```
FLASK_SECRET_KEY="..."

GOOGLE_AUTH_URL=https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent
GOOGLE_AUTH_SCOPE="openid email profile"
GOOGLE_AUTH_TOKEN_URI=https://oauth2.googleapis.com/token
GOOGLE_AUTH_REDIRECT_URI=http://localhost:5000/login/callback
GOOGLE_AUTH_USER_INFO_URL=https://www.googleapis.com/userinfo/v2/me
GOOGLE_AUTH_CLIENT_ID="..."
GOOGLE_AUTH_CLIENT_SECRET="..."
```
Add it to the application:
```
app = Dash(__name__)

from dash_google_oauth.google_auth import GoogleAuth
auth = GoogleAuth(app)
```
You have access to `/logout` route in order to logout user by making a `GET` request.

User's name stored in cookie: `flask.request.cookies.get('AUTH-USER')`