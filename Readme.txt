
Logo
Authorization Microservice
A microservice to create user and get its information.
Explore the docs »

View Demo · Report Bug · Request Feature

Table of Contents
About The Project
For the ecommerce project, we needed a microservice for creating and manipulating users. So we created this microservice.

This microservice will do:

create user
edit user
edit password
forget password
authorize user
delete user
add role
edit role 
etc ...
We have specified a schema for the product; Here is an example:

{
    "user_id": 1,
    "password": "pbkdf2_sha256$260000$4RfyhdrZOuQyDhk8ylNmUM$lEc2Xrnou0c2hOy4TsfiMHxT7H4V5PYbYe4viFBhvvc=",
    "last_login": {
        "$date": "2023-02-13T12:55:24.257Z"
    },
    "email": "mohsen11.u3fi@hotmail.com",
    "username": "admin",
    "usertype": "1",
    "is_active": true,
    "is_admin": true,
    "first_name": "admin",
    "last_name": "",
    "user_group": "admin",
    "is_marketplace": false
}

(back to top)

Built With
In this project, we used the following technologies:

Python
Mongo DB
Django
Later, Vue.js may included.
(back to top)

Getting Started
In this part, there is an instructions on setting up the project locally. To get a local copy up and running follow these simple steps.

Prerequisites
For this project, you need python v3.9 and mongodb v5Install MongoDB Community Edition

Installation
After installing prerequisites, now you can install dependencies of this project:

Clone the repo

git clone https://github.com/gitAnzh/authentication-authorization.git
Setup an environment

sudo apt install python3-virtualenv
virtualenv venv
source venv/bin/activate
Install pip packages

pip install -r requirements.txt
In main directory(where setup.py file is) use this command to install the project

pip install -e .
(back to top)

Usage
To run the project, make sure that the mongodb service is up locally and run this in the app directory

python main.py
You can visit localhost:8000 for root directory.
(back to top)

Database Visualization
Download mongodb compass: MongoDB Compass

(back to top)

Fork the Project
Create your Feature Branch (git checkout -b feature/AmazingFeature)
Commit your Changes (git commit -m 'Add some AmazingFeature')
Push to the Branch (git push origin feature/AmazingFeature)
Open a Pull Request
(back to top)

License
All rights reserved

(back to top)

Contact
mohsen yousefi - mohsen.u3fi@hotmail.com

Project Link: https://github.com/gitAnzh/authentication-authorization.git

(back to top)
