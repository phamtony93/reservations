from flask import Flask, Blueprint, render_template, request
import reservations
import restaurants
from requests_oauthlib import OAuth2Session
import json
from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests


app = Flask(__name__)
app.register_blueprint(reservations.bp)
app.register_blueprint(restaurants.bp)

# Disables the requirement to use HTTPS to test locally
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

#copy from OAuth2 Credential section at
#https://console.cloud.google.com/apis/credentials
client_id = r'62478017401-losb1tdvnpigaai16j0tcr4v28s3ggf3.apps.googleusercontent.com'
client_secret = r'hWJxOWhiC5dWaWsqrpTNA8PD'
url_base = 'http://localhost:5000'
redirect_uri = url_base + '/oauth'

# #Part of Google People API to get basic info to identify a user
scope = ['https://www.googleapis.com/auth/userinfo.email',
             'https://www.googleapis.com/auth/userinfo.profile', 'openid']
oauth = OAuth2Session(client_id, redirect_uri=redirect_uri,
                          scope=scope)

redirect_uri = 'http://localhost:5000/oauth'

def getSubFromJWT(token):
    claims = jwt.decode(token, verify=False)
    return claims['sub']

def verifyJWT(token, client_id):
    req = requests.Request()

    try:
        id_info = id_token.verify_oauth2_token(
            token, req, client_id)
        return id_info
    except ValueError:
        return '401'

@app.route('/')
def index():
    authorization_url, state = oauth.authorization_url(
        'https://accounts.google.com/o/oauth2/auth',
        # access_type and prompt are Google specific extra
        # parameters.
        access_type="offline", prompt="select_account")
    return 'Please go <a href=%s>here</a> and authorize access.' % authorization_url

@app.route('/oauth')
def oauthroute():
    token = oauth.fetch_token(
        'https://accounts.google.com/o/oauth2/token',
        authorization_response=request.url,
        client_secret=client_secret)
    req = requests.Request()

    id_info = id_token.verify_oauth2_token( 
    token['id_token'], req, client_id)
    claims = jwt.decode(token['id_token'], verify=False)
    sub = claims['sub']
    print(sub)

    return f"Your JWT is : {token['id_token']}" #% token['id_token'], claims

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)