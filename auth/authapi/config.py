import pika
import pymongo


# database connection
class db_connection:
    # myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    myclient = pymongo.MongoClient('200.100.100.220', username='root', password='qweasdQWEASD')
    mydb = myclient["auth"]
    access_app_col = mydb["authapi_access"]
    user_col = mydb['authapi_user']
    access_api_col = mydb['access_api']
    access_group = mydb['user_group']
    token_col = mydb['authtoken_token']

    rabbit_connection = pika.URLParameters('amqp://rbtmq:DeVrab!t123@200.100.100.205:5672/%2F')
    queue_name = "auth"
