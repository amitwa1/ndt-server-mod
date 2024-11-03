

import time
import json
import jwt

def generate_jwt():
    current_time_in_seconds = round(time.time())
    expiry_time_in_seconds = current_time_in_seconds + 600
    audience = "å"
    claims={"exp": expiry_time_in_seconds, "iat":current_time_in_seconds}
    jwk={
          "kty": "EC",
          "crv": "P-256",
          "alg": "ES256",
          "x": "QceRrbFnnpVLjJc7wi9CqLxi1PT05r9M0kSQQrO9WuI",
          "y": "EyxzzVgL2iW7HOfay_T8Zsc3-T8RhUf5SilFdZfKBoY",
          "d": "Z1rE8_xjZ_cT-DRvVz18I6_KyHSkjjIXUdOKt8XBqH8"
        }

    private_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps({
                                                                            "kty": "EC",
                                                                            "crv": "P-256",
                                                                            "alg": "ES256",
                                                                            "x": "QceRrbFnnpVLjJc7wi9CqLxi1PT05r9M0kSQQrO9WuI",
                                                                            "y": "EyxzzVgL2iW7HOfay_T8Zsc3-T8RhUf5SilFdZfKBoY",
                                                                            "d": "Z1rE8_xjZ_cT-DRvVz18I6_KyHSkjjIXUdOKt8XBqH8"
                                                                          }))
    signed_jwt = jwt.encode(claims, private_key, algorithm="RS256")
    print(signed_jwt)


generate_jwt()
