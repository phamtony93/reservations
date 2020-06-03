from flask import Flask, Blueprint, make_response, request
from google.cloud import datastore
import json
import constants
from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests

url_base = 'localhost:5000'
url_prefix = '/restaurants'
bp = Blueprint('restaurants', __name__, url_prefix=url_prefix)
client = datastore.Client()
client_id = r'62478017401-losb1tdvnpigaai16j0tcr4v28s3ggf3.apps.googleusercontent.com'
client_secret = r'hWJxOWhiC5dWaWsqrpTNA8PD'

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
def resturants_get():
    res = {}
    if request.method == 'GET':
        query = client.query(kind=constants.restaurants)
        results = list(query.fetch())
        for e in results:
            e['id'] = e.key.id
            e['self'] = url_prefix + url_prefix + '/' + str(e['id'])
        res = results
        res = make_response(json.dumps(res))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    elif request.method == 'POST':
        if (request.content_type != 'application/json'):
            res['Error'] = 'Invalid content type. Please send as json'
            return (json.dumps(res), 415)
        contents = request.get_json()
        sub = validateCustomerID(request, client_id)
        if (sub == '401'):
            res['Error'] = 'Invalid or missing authorization token'
            return (json.dumps(res), 401)
        hasName = "name" in contents
        hasType = "type" in contents
        hasCapacity = "capacity" in contents
        if (not hasName or not hasType or not hasCapacity):
            res['Error'] = 'The request is missing a required attribute'
            return (json.dumps(res), 400)
        #Check if attributes are string values
        #check if attributes are alphanumeric
        #check if capacity valid numeric string
        #check for duplicate restaurants
        query = client.query(kind=constants.restaurants)
        query.add_filter('name', '=', contents['name'])
        results = list(query.fetch())
        print(results)
        if (results):
            res['Error'] = 'There is already a restaurant with this name'
            return (json.dumps(res), 403)
        restaurant_key = client.key(constants.restaurants)
        new_restaurant = datastore.entity.Entity(key=restaurant_key)
        new_restaurant.update({"name": contents['name'], "type": contents['type'], "capacity": contents['capacity'], "number of reservations": "0"})
        client.put(new_restaurant)
        new_restaurant['id'] = new_restaurant.key.id
        new_restaurant['self'] = url_base + url_prefix + '/' + str(new_restaurant['id'])
        res = new_restaurant
        res = make_response(json.dumps(res))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 201
        return res
    else:
        res['Error'] = 'Method not recognized'
        return (json.dumps(res), 405)

@bp.route('/<restaurant_id>', methods=['GET', 'DELETE', 'PATCH', 'PUT'])
def get_delete_edit_replace_restaurant(restaurant_id):
    res = {}
    if request.method == 'GET':
        # sub = validateCustomerID(request, client_id)
        # if (sub == '401'):
        #     res['Error'] = 'Invalid or missing authorization token'
        #     return (json.dumps(res), 401)
        mediaAccepted = request.headers.get("accept")
        if (mediaAccepted != "application/json" and mediaAccepted != "*/*"):
            res['Error'] = 'Media Not Acceptable'
            return (json.dumps(res), 406)
        restaurant_key = client.key(constants.restaurants, int(restaurant_id))
        restaurant = client.get(restaurant_key)
        if (not restaurant):
            res['Error'] = 'A restaurant with this restaurant_id does not exist'
            return (json.dumps(res), 404)
        restaurant['id'] = restaurant.key.id
        restaurant['self'] = url_base + url_prefix + '/' + str(restaurant['id'])
        res = restaurant
        res = make_response(json.dumps(res))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    elif request.method == 'PATCH':
        if (request.content_type != 'application/json'):
            res['Error'] = 'Content-Type must be application/json'
            return (json.dumps(res), 415)
        contents = request.get_json()
        #Check if request body is null
        #Check for unique name
        #check for string attributes
        #check for alphanumeric
        hasName = 'name' in contents
        hasType = 'type' in contents
        hasCapacity = 'capacity' in contents
        if (not hasName and not hasType and not hasCapacity):
            res['Error'] = 'The request is missing a required attribute'
            return (json.dumps(res), 400)
        restaurant_key = client.key(constants.restaurants, int(restaurant_id))
        restaurant = client.get(restaurant_key)
        if (not restaurant):
            res['Error'] = 'A restaurant with this restaurant_id does not exist'
            return (json.dumps(res), 404)
        if (hasName):
            restaurant['name'] = contents['name']
        if (hasType):
            restaurant['type'] = contents['type']
        if (hasCapacity):
            restaurant['capacity'] = contents['capacity']
        client.put(restaurant)
        return ('', 200)
    elif request.method == 'PUT':
        if (request.content_type != 'application/json'):
            res['Error'] = 'Content-Type must be application/json'
            return (json.dumps(res), 415)
        mediaAccepted = request.headers.get("accept")
        if (mediaAccepted != "application/json" and mediaAccepted != "*/*"):
            res['Error'] = "Media Not Acceptable"
            return (json.dumps(res), 406)
        contents = request.get_json()
        hasName = 'name' in contents
        hasType = 'type' in contents
        hasCapacity = 'capacity' in contents
        if (not hasName or not hasType or not hasCapacity):
            res['Error'] = 'The request is missing a required attributes'
            return (json.dumps(res), 400)
        restaurant_key = client.key(constants.restaurants, int(restaurant_id))
        restaurant = client.get(restaurant_key)
        if (not restaurant):
            res['Error'] = 'A restaurant with this restaurant_id does not exist'
            return (json.dumps(res), 404)
        restaurant.update({"name": contents['name'], "type": contents['type'], "capacity": contents['capacity']})
        client.put(restaurant)
        restaurant['id'] = restaurant.key.id
        restaurant['self'] = url_base + url_prefix + '/' + str(restaurant['id'])
        res = restaurant
        res = make_response(json.dumps(res))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    elif request.method == 'DELETE':
        restaurant_key = client.key(constants.restaurants, int(restaurant_id))
        restaurant = client.get(restaurant_key)
        if (not restaurant):
            res['Error'] = 'A restaurant with this restaurant_id does not exist'
            return (json.dumps(res), 404)
        client.delete(restaurant)
        return ('', 204)

    else: 
        res['Error'] = 'Method not recognized'
        return (json.dumps(res), 405)