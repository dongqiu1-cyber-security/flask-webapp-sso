from fastapi import Cookie, FastAPI, Response, HTTPException
import uvicorn
from typing import Annotated
from fastapi.responses import RedirectResponse
from urllib.parse import urlparse,urlencode
import requests
import jwt
import json
from fastapi.middleware.cors import CORSMiddleware
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"],  # Adjust the port based on your Vue.js dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str = None, session_token: str | None = Cookie(default=None)):
    logger.info('Received login request')
    logger.info('session_token: ' + str(session_token))
    if session_token:
        logger.info('Session token found in cookie')
        logger.info('Validating session token')
        result = token_validation(session_token)
        logger.info('Session token validation result: ' + str(result))

        if 'error' in result:
            return result

        username = result['preferred_username']
        # name = result['name']

        return {"item_id": item_id, "q": q, "username": username}
    else:
        # redirect to auth
        clientId = 'test1'
        state = f'/items/{item_id}'
        redirectUri = "http://localhost:3000/sso"
        params = {
            "response_type": "code",
            "client_id": clientId,
            "state": state,
            "scope": "openid profile email",
            "redirect_uri": redirectUri
        }
        idp_auth_url = f'http://localhost:18080/realms/master/protocol/openid-connect/auth?{urlencode(params)}'
        # Instead of redirecting, raise an HTTPException with a 401 status code
        raise HTTPException(
            status_code=401,
            detail={"message": "Unauthorized", "redirect_url": idp_auth_url}
        )

@app.get("/sso")
def read_sso(code: str, state: str):
    # get token from token endpoint
    # exchange a token from authorization_code
    logger.info('Received SSO callback')
    logger.info('code: ' + code)
    logger.info('state: ' + state)
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost:3000/sso",
        "client_id": "test1",
        "client_secret": "eVxInnbOFzslpdNNy8uwNcMIhiDCX9Ps" # Confirm the client secret in Keycloak at Clients -> test1 -> Credentials
    }
    headers={"Content-Type": "application/x-www-form-urlencoded"}
    logger.info('Requesting token from token endpoint in IdP')
    res = requests.post('http://localhost:18080/realms/master/protocol/openid-connect/token', data=payload, headers=headers)
    # logger.info(f'Response: {res.json()}')
    access_token = res.json()['access_token']
    logger.info(f'Access token: {access_token}')
    id_token = res.json()['id_token']
    logger.info(f'Id token: {id_token}')

    result = token_validation(id_token)
    logger.info('Token validation result: ' + str(result))
    result = token_validation(access_token)
    logger.info('Token validation result: ' + str(result))

    response = RedirectResponse(f'http://localhost:3000{state}')
    response.set_cookie(key="session_token", value=access_token, max_age=60, path="/")
    #  return RedirectResponse(f'http://localhost:8080{state}'
    #  return {"code": code, "access_token": access_token, "id_token": id_token}
    return response



def token_validation(token):
    # verify id_token
    # get public key
    logger.info('Validating token')
    API_AUDIENCE = 'test1' # Confirm the audience in Keycloak at Clients -> test1 -> Client Scopes -> openid-connect -> Mappers -> Audience; It should be the same as the client_id
    res = requests.get('http://localhost:18080/realms/master/protocol/openid-connect/certs')
    jwks = res.json()

    # jwks can have multiple keys in different algorithms ex: RSA-OAEP or RS256
    # id_token is signed by either keys
    # assume this id_token is signed by RS256, and it's in the 2nd entry in jwks
    # kid (key id) must match as well.

    unverified_header = jwt.get_unverified_header(token)
    sigAlgo = unverified_header['alg']
    sigKid = unverified_header['kid']

    key = None

    for x in jwks['keys']:
        if x['kid'] == sigKid:
            key = jwt.algorithms.RSAAlgorithm.from_jwk(x)
    # Convert the RSA public key back to JWK for readable logging
    key_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key)
    # Log the key object as human-readable JSON
    logger.info(f"Key as JWK: {key_jwk}")

    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=sigAlgo,
            audience=API_AUDIENCE,
            issuer='http://localhost:18080/realms/master',
            #  options={"verify_signature": False}
        )
    except Exception as e:
        logger.error(e)
        # verification error
        return {"state": "user not authenticated", "error": True}

    return payload



if __name__ == "__main__":
    logger.info("Starting server")
    uvicorn.run(app, host="0.0.0.0", port=3000, log_level="debug")
