from flask import Flask, Blueprint, make_response, request
from google.cloud import datastore
import json
import constants
from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests

url_base = 'localhost:5000'
url_prefix = '/reservations'
bp = Blueprint('reservations', __name__, url_prefix=url_prefix)
client = datastore.Client()
client_id = r'62478017401-losb1tdvnpigaai16j0tcr4v28s3ggf3.apps.googleusercontent.com'
client_secret = r'hWJxOWhiC5dWaWsqrpTNA8PD'

# def getSubFromJWT(token):
#     claims = jwt.decode(token, verify=False)
#     return claims['sub']

def verifyJWT(token, client_id):
    req = requests.Request()

    try:
        id_info = id_token.verify_oauth2_token(
            token, req, client_id)
        return id_info
    except ValueError:
        return '401'    

def validateCustomerID(request, client_id):
    authToken = request.headers.get("Authorization")
    if (not authToken):
        return '401'
    authToken = authToken[7:]
    jwtDecoded = verifyJWT(authToken, client_id)
    if (jwtDecoded == '401'):
        return '401'
    return jwtDecoded['sub']

@bp.route('', methods=['GET', 'POST'])
def get_reservations():
    res = {}
    if request.method == "GET":
        #Implement JWT
        # authToken = request.headers.get("Authorization")
        # if (not authToken):
        #     res['Error'] = 'Invalid or missing authorization token'
        #     return (json.dumps(res), 401)
        # authToken = authToken[7:]
        # jwtDecoded = verifyJWT(authToken, client_id)
        # if (jwtDecoded == '401'):
        #     res['Error'] = 'Invalid or missing authorization token'
        #     return (json.dumps(res), 401)
        # sub = jwtDecoded['sub']
        sub = validateCustomerID(request, client_id)
        print(sub)
        if (sub == '401'):
            res['Error'] = 'Invalid or missing authorization token'
            return (json.dumps(res), 401)    
        query = client.query(kind=constants.reservations)
        query.add_filter('customer', '=', sub)
        results = list(query.fetch())
        for e in results:
            e['id'] = e.key.id
            e['self'] = url_base + url_prefix + '/' + str(e['id'])
        res = results
        res = make_response(json.dumps(res))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    elif request.method == "POST":
        sub = validateCustomerID(request, client_id)
        if (sub == '401'):
            res['Error'] = 'Invalid or missing authorization token'
            return (json.dumps(res), 401)
        #Check for required values!
        
        contents = request.get_json()
        reservation_key = client.key(constants.reservations)
        new_reservation = datastore.entity.Entity(key=reservation_key)
        new_reservation.update({"restaurant": contents["restaurant"], "customer": sub, "size" : contents["size"], "time": contents["time"]})
        client.put(new_reservation)
        new_reservation['id'] = new_reservation.key.id
        new_reservation['self'] = url_base + url_prefix + '/' + str(new_reservation['id'])
        res = new_reservation
        res = make_response(json.dumps(res))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 201
        return res
    else:
        res['Error'] = 'Method not recognized'
        return (json.dumps(res), 405)
        
@bp.route('/<reservation_id>', methods=['GET', 'DELETE'])
def reservation_id_get_delete(reservation_id):
    res = {}
    if request.method == 'GET':
        sub = validateCustomerID(request, client_id)
        if (sub == '401'):
            res['Error'] = 'Invalid or missing authorization token'
            return (json.dumps(res), 401)
        reservation_key = client.key(constants.reservations, int(reservation_id))
        reservation = client.get(reservation_key)
        if (not reservation):
            res['Error'] = 'A reservation with this id does not exist'
            return (json.dumps(res), 404)
        if (reservation['customer'] != sub):
            res['Error'] = 'This reservation belongs to another customer'
            return (json.dumps(res), 403)            
        reservation['id'] = reservation.key.id
        reservation['self'] = url_base + url_prefix + '/' + str(reservation['id'])
        res = reservation
        res = make_response(json.dumps(res))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    elif request.method == 'DELETE':
        sub = validateCustomerID(request, client_id)
        if (sub == '401'):
            res['Error'] = 'Invalid or missing authorization token'
            return (json.dumps(res), 401)
        reservation_key = client.key(constants.reservations, int(reservation_id))
        reservation = client.get(reservation_key)
        if (not reservation):
            res['Error'] = 'A reservation with this id does not eixst'
            return (json.dumps(res), 404)
        if (reservation['customer'] != sub):
            res['Error'] = 'This reservation belogns to another customer'
            return (json.dumps(res), 403) 
        client.delete(reservation_key)
        return ('', 204)
    else:
        res['Error'] = 'Method not recognized'
        return (json.dumps(res), 405)