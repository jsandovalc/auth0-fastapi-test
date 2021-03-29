from os import environ as env
from jose import jwt
import httpx
from typing import Optional
from fastapi import FastAPI, Header
from fastapi import FastAPI, HTTPException

app = FastAPI()


AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
API_IDENTIFIER = env.get("API_IDENTIFIER")
API_AUDIENCE = API_IDENTIFIER
ALGORITHMS = ["RS256"]


@app.get("/")
async def home(authorization: Optional[str] = Header(None)):
    """An example of using auth0 for authentication.

    Every authenticated request must perform this check. It can go as a
    decorator, as a function or maybe, as a dependency injected named user.

    """
    auth = authorization

    if not auth:
        print(":( no authorization header sent")
        raise HTTPException(detail="No token sent", status_code=401)

    prefix, token = auth.split()

    if prefix.lower != "bearer":
        print("Bearer is the recommended, but we'll support JWT for Rextie.")

    async with httpx.AsyncClient() as client:
        r = await client.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
        jwks = r.json()
        unverified_header = jwt.get_unverified_header(token)

        rsa_key = {}

        for key in jwks["keys"]:
            print(f"{key=}, {unverified_header=}")
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://"+AUTH0_DOMAIN+"/"
                )
            except jwt.ExpiredSignatureError:
                raise HTTPException(detail="token is expired", status_code=401)
            except jwt.JWTClaimsError:
                raise HTTPException(detail="incorrect claims,", status_code=401)
            except Exception:
                raise HTTPException(detail="Unable to parse authentication", status_code=401)


    return {"Hello": "World"}
