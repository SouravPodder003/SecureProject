=> Signup Request:
POST http://localhost:5000/signup
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepass"
}



=> Signin Request:
POST http://localhost:5000/signin
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "securepass"
}

=> Response:
{
  "message": "Logged in successfully",
  "token": "<your_jwt_token>"
}




=> Message Post:
POST http://localhost:5000/messages
Content-Type: application/json
Authorization: Bearer <your_jwt_token>

{
  "message": "Hey everyone!"
}





=> Get all messages:
GET http://localhost:5000/messages
Authorization: Bearer <your_jwt_token>


=> Response:
[
  {
    "message": "Hey everyone!",
    "timestamp": "2025-04-22 15:30:00",
    "username": "john_doe"
  }
]




