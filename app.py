from flask import Flask, request, abort
from functools import wraps
import jwt
from jwt import PyJWKClient
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
)

app = Flask(__name__)

AUTH0_DOMAIN = 'fsndmms.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'image'

def verify_decode_jwt(token: str):
    jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    try:
        jwks_client = PyJWKClient(jwks_url)
        signing_key = jwks_client.get_signing_key_from_jwt(token).key

        payload = jwt.decode(
            token,
            signing_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
            options={"require": ["exp", "iss", "aud"]},  # opcional, mas recomendável
        )
        return payload

    except ExpiredSignatureError:
        return None  # token expirado
    except (InvalidAudienceError, InvalidIssuerError):
        return None  # 'aud' ou 'iss' inválidos
    except InvalidTokenError:
        return None  # assinatura inválida, claims faltando, etc.


def get_jwt():
  
  if not ('Authorization' in request.headers):
    abort(401)
  
  authorz_data = request.headers['Authorization'].split(' ')
  
  if authorz_data[0] != 'Bearer':
    abort(400)
  elif len(authorz_data) != 2:
    abort(401)

  return authorz_data[1]
  
def check_permissions(permission,payload):
  if 'permissions' not in payload:
    abort(401)
  
  if permission not in payload['permissions']:
     abort(403, description='Você não tem a autorização necessária para esse acesso!')

  return True
    

def check_authorization(permission=''):
  def check_authentication(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
      jwt = get_jwt()

      payload = verify_decode_jwt(jwt)
      
      if payload is None:
              abort(401, description="Token inválido ou expirado")

      check_permissions(permission,payload)

      return func(payload,*args,**kwargs)
    return wrapper
  return check_authentication

@app.route('/image')
@check_authorization('get:images')
def headers(rec_jwt):
  print(rec_jwt)
  return 'Not implemented!'