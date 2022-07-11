import json

import requests
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.utils.encoding import force_bytes, smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.decorators.csrf import csrf_exempt
from rest_framework import generics, permissions
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_201_CREATED, HTTP_401_UNAUTHORIZED, \
    HTTP_204_NO_CONTENT, HTTP_203_NON_AUTHORITATIVE_INFORMATION

from .config import db_connection
from .funcs import set_access
from .models import User
from .rpcClient import Get
from .serializers import EditUserSerializer, UserLoginSerializer, \
    ChangePasswordSerializer, RegisterSerializers, GroupSerializer, AccessGroupSerializer, ResetPasswordEmail, \
    SetNewPasswordSerializer
from .utils import Util


@csrf_exempt
@api_view(['POST'])
@permission_classes((AllowAny,))
def LoginMarketplace(request, format=None):
    if request.method == 'POST':
        global marketplace
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            if 'username' in serializer.validated_data:
                password = serializer.validated_data['password']
                username = serializer.validated_data['username']
                user = authenticate(username=username, password=password)  # check username and password
                user_detail = db_connection.user_col.find({"username": username})
                for item in user_detail:
                    marketplace = item['is_marketplace']
                if user is not None:
                    # check marketplace access for login if true
                    if user.is_active and marketplace:
                        try:
                            login(request, user)
                            # create token for user
                            user_token = Token.objects.get_or_create(user=user)
                            user_token = user_token[0]
                            user_token = user_token.key

                            # response for login
                            myquery = {"user_id": user.user_id}
                            access = db_connection.access_app_col.find(myquery)
                            user_data = db_connection.user_col.find(myquery)
                            result_access = []
                            for cursor_access in access:
                                if '_id' in cursor_access:
                                    del cursor_access['_id']
                                    result_access.append(cursor_access)

                            for cursor_user in user_data:
                                del cursor_user['_id']
                                del cursor_user['password']
                                del cursor_user['is_admin']
                                del cursor_user['is_active']
                                user_details = {'id': cursor_user['user_id'], 'username': cursor_user['username'],
                                                'token': user_token,
                                                'usertype': cursor_user['usertype'],
                                                'first_name': cursor_user['first_name'],
                                                'last_name': cursor_user['last_name'],
                                                "is_marketplace": cursor_user['is_marketplace'],
                                                'access': result_access}
                                db_connection.myclient.close()
                                return Response(user_details, status=HTTP_200_OK)

                        except:
                            db_connection.myclient.close()
                            user_details = {"something went wrong!!"}
                            return Response(user_details, status=HTTP_200_OK)
                    else:
                        db_connection.myclient.close()
                        data_response = {"message": "Username or password invalid or you dont have access"}
                        return Response(data_response, status=HTTP_401_UNAUTHORIZED)
                else:
                    db_connection.myclient.close()
                    data_response = {"message": "Please insert your username!"}
                    return Response(data_response, status=HTTP_401_UNAUTHORIZED)
        else:
            db_connection.myclient.close()
            data_response = {"message": serializer.errors}
            return Response(data_response, status=HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        qs = []
        return qs


@csrf_exempt
@api_view(['POST'])
@permission_classes((AllowAny,))
def LoginUserView(request, format=None):
    if request.method == 'POST':
        global marketplace
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            if 'username' in serializer.validated_data:
                password = serializer.validated_data['password']
                username = serializer.validated_data['username']
                user = authenticate(username=username, password=password)  # check username and password
                user_detail = db_connection.user_col.find({"username": username})
                for item in user_detail:
                    marketplace = item['is_marketplace']
                if user is not None:
                    if user.is_active and not marketplace:
                        try:
                            login(request, user)
                            # create token for user
                            user_token = Token.objects.get_or_create(user=user)
                            user_token = user_token[0]
                            user_token = user_token.key
                            # response for login

                            myquery = {"user_id": user.user_id}
                            access = db_connection.access_app_col.find(myquery)
                            user_data = db_connection.user_col.find(myquery)
                            result_access = []
                            for cursor_access in access:
                                if '_id' in cursor_access:
                                    del cursor_access['_id']
                                    result_access.append(cursor_access)
                            # result_user = [{"token": user_token}]
                            for cursor_user in user_data:
                                del cursor_user['_id']
                                del cursor_user['password']
                                del cursor_user['is_admin']
                                del cursor_user['is_active']
                                user_details = {'id': cursor_user['user_id'], 'username': cursor_user['username'],
                                                'token': user_token,
                                                'usertype': cursor_user['usertype'],
                                                'first_name': cursor_user['first_name'],
                                                'last_name': cursor_user['last_name'],
                                                "is_marketplace": cursor_user['is_marketplace'],
                                                'access': result_access}
                                db_connection.myclient.close()
                                return Response(user_details, status=HTTP_200_OK)

                        except:
                            db_connection.myclient.close()
                            user_details = {"Djongo didnt response! call ahmad"}
                            return Response(user_details, status=HTTP_200_OK)
                    else:
                        db_connection.myclient.close()
                        data_response = {"message": "Username or password invalid or you dont have access"}
                        return Response(data_response, status=HTTP_401_UNAUTHORIZED)
                else:
                    db_connection.myclient.close()
                    data_response = {"message": "Please insert your username!"}
                    return Response(data_response, status=HTTP_401_UNAUTHORIZED)
        else:
            db_connection.myclient.close()
            data_response = {"message": serializer.errors}
            return Response(data_response, status=HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        qs = []
        return qs


@api_view(['POST'])
@permission_classes((AllowAny,))
def RegisterUserView(request, format=None):
    serializer = RegisterSerializers(data=request.data)
    if serializer.is_valid():
        try:
            last_name = ''
            first_name = ''
            password = serializer.validated_data['password']
            if 'last_name' in serializer.validated_data:
                last_name = serializer.validated_data['last_name']
            if 'first_name' in serializer.validated_data:
                first_name = serializer.validated_data['first_name']
            if 'email' in serializer.validated_data and 'username' in serializer.validated_data:
                email = serializer.validated_data['email']
                username = serializer.validated_data['username']
                usertype = serializer.validated_data['usertype']
                is_admin = serializer.validated_data['is_admin']
                is_marketplace = serializer.validated_data['is_marketplace']
                user = User.objects.create(username=username,
                                           email=email,
                                           first_name=first_name,
                                           last_name=last_name,
                                           usertype=usertype,
                                           is_admin=is_admin,
                                           is_marketplace=is_marketplace
                                           )
                # Set password for user
                user.set_password(password)
                # Save user
                user.save()
                set_access.set_access_view(user.user_id)

                data_response = {"user_id": user.user_id, 'username': username, 'email': email,
                                 'first_name': first_name, 'last_name': last_name, 'usertype': usertype,
                                 'is_admin': is_admin}
                db_connection.myclient.close()
                return Response(data_response, status=HTTP_201_CREATED)
        except:
            db_connection.myclient.close()
            data_response = {"message": "Djongo didnt response! call ahmad"}
            return Response(data_response, status=HTTP_400_BAD_REQUEST)
    else:
        db_connection.myclient.close()
        data_response = {"message": serializer.errors}
        return Response(data_response, status=HTTP_400_BAD_REQUEST)


def get_queryset(self):
    qs = []
    return qs


class ChangePasswordView(generics.ListAPIView):
    lookup_field = 'pk'
    serializer_class = ChangePasswordSerializer
    permission_classes = [
        permissions.IsAuthenticated
    ]

    def post(self, request, format=None):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            user = self.request.user
            check_password = user.check_password(old_password)
            if check_password:
                user.set_password(new_password)
                user.save()
                data_response = {'message': 'Password Successfully Changed'}
                return Response(data_response, status=HTTP_200_OK)
            else:
                data_response = {"message": "Invalid Password"}
                return Response(data_response, status=HTTP_400_BAD_REQUEST)
        else:
            data_response = {"message": serializer.errors}
            return Response(data_response, status=HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        qs = []
        return qs


@api_view(['POST'])
@permission_classes((AllowAny,))
def CheckToken(request, format=None):
    data = {
        "key": request.data['key'],
        "api": request.data['api']
    }
    data = json.dumps(data)
    type = 'get'
    content_type = 'token'
    rpc = Get()
    mq_call = rpc.call(type, content_type, data)
    return Response(mq_call)


# get user detail and edit with primary key
class EditUserView(generics.ListAPIView):
    lookup_field = 'pk'
    serializer_class = EditUserSerializer
    permission_classes = [
        permissions.IsAdminUser
    ]

    def put(self, request, pk):
        serializer = EditUserSerializer(data=request.data)
        if serializer.is_valid():
            data_response = {}
            # Update user collection
            user_detail = db_connection.user_col.find({"user_id": pk})
            for cursor_detail in user_detail:
                del cursor_detail["_id"]
                for cursor in list(dict(cursor_detail).keys()):
                    if cursor in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor]
                        myquery = {"user_id": pk}
                        newvalue = {"$set": {cursor: request.data[cursor]}}
                        db_connection.user_col.update(myquery, newvalue)
                        data_response[f'{cursor} successfully changed to'] = updated_value

            # Update auth_access collection

            access_detail = db_connection.access_app_col.find({"user_id": pk})
            for app_detail in access_detail:
                del app_detail["_id"]

                for cursor_wms in list(dict(app_detail['Wms']).keys()):
                    if cursor_wms in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor_wms]
                        myquery = {"user_id": pk}
                        find_place = str('Wms.' + cursor_wms)
                        newvalue = {"$set": {find_place: request.data[cursor_wms]}}
                        db_connection.access_app_col.update(myquery, newvalue)
                        data_response[f'{cursor_wms} successfully changed to'] = updated_value

                for cursor_crm in list(dict(app_detail['Crm']).keys()):
                    if cursor_crm in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor_crm]
                        myquery = {"user_id": pk}
                        find_place = str('Crm.' + cursor_crm)
                        newvalue = {"$set": {find_place: request.data[cursor_crm]}}
                        db_connection.access_app_col.update(myquery, newvalue)
                        data_response[f'{cursor_crm} successfully changed to'] = updated_value

                for cursor_scm in list(dict(app_detail['SCM']).keys()):
                    if cursor_scm in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor_scm]
                        myquery = {"user_id": pk}
                        find_place = str('SCM.' + cursor_scm)
                        newvalue = {"$set": {find_place: request.data[cursor_scm]}}
                        db_connection.access_app_col.update(myquery, newvalue)
                        data_response[f'{cursor_scm} successfully changed to'] = updated_value

                for cursor_catalog in list(dict(app_detail['Catalog']).keys()):
                    if cursor_catalog in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor_catalog]
                        myquery = {"user_id": pk}
                        find_place_catalog = str('Catalog.' + cursor_catalog)
                        newvalue = {"$set": {find_place_catalog: request.data[cursor_catalog]}}
                        db_connection.access_app_col.update(myquery, newvalue)
                        data_response[f'{cursor_catalog} successfully changed to'] = updated_value

                for cursor_accounting in list(dict(app_detail['Accounting']).keys()):
                    if cursor_accounting in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor_accounting]
                        myquery = {"user_id": pk}
                        find_place = str('Accounting.' + cursor_accounting)
                        newvalue = {"$set": {find_place: request.data[cursor_accounting]}}
                        db_connection.access_app_col.update(myquery, newvalue)
                        data_response[f'{cursor_accounting} successfully changed to'] = updated_value

                for cursor_accounting in list(dict(app_detail['Logistic']).keys()):
                    if cursor_accounting in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor_accounting]
                        myquery = {"user_id": pk}
                        find_place = str('Logistic.' + cursor_accounting)
                        newvalue = {"$set": {find_place: request.data[cursor_accounting]}}
                        db_connection.access_app_col.update(myquery, newvalue)
                        data_response[f'{cursor_accounting} successfully changed to'] = updated_value

                for cursor_accounting in list(dict(app_detail['Marketplace']).keys()):
                    if cursor_accounting in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor_accounting]
                        myquery = {"user_id": pk}
                        find_place = str('Marketplace.' + cursor_accounting)
                        newvalue = {"$set": {find_place: request.data[cursor_accounting]}}
                        db_connection.access_app_col.update(myquery, newvalue)
                        data_response[f'{cursor_accounting} successfully changed to'] = updated_value

            # Update api CRM access object
            access_api_detail = db_connection.access_api_col.find({"user_id": pk})
            for api_detail in access_api_detail:
                del api_detail["_id"]
                for cursor in list(dict(api_detail['crm_api_access']).keys()):
                    if cursor in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor]
                        myquery = {"user_id": pk}
                        find_place = str('crm_api_access.' + cursor)
                        newvalue = {"$set": {find_place: request.data[cursor]}}
                        db_connection.access_api_col.update(myquery, newvalue)
                        data_response[f'{cursor} successfully changed to'] = updated_value

            # Update api SCM access object
            access_api_detail = db_connection.access_api_col.find({"user_id": pk})
            for api_detail in access_api_detail:
                del api_detail["_id"]
                for cursor in list(dict(api_detail['scm_api_access']).keys()):
                    if cursor in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor]
                        myquery = {"user_id": pk}
                        find_place = str('scm_api_access.' + cursor)
                        newvalue = {"$set": {find_place: request.data[cursor]}}
                        db_connection.access_api_col.update(myquery, newvalue)
                        data_response[f'{cursor} successfully changed to'] = updated_value

            # Update api accounting access object
            access_api_detail = db_connection.access_api_col.find({"user_id": pk})
            for api_detail in access_api_detail:
                del api_detail["_id"]
                for cursor in list(dict(api_detail['accounting_api_access']).keys()):
                    if cursor in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor]
                        myquery = {"user_id": pk}
                        find_place = str('accounting_api_access.' + cursor)
                        newvalue = {"$set": {find_place: request.data[cursor]}}
                        db_connection.access_api_col.update(myquery, newvalue)
                        data_response[f'{cursor} successfully changed to'] = updated_value

            # Update api warehouse access object
            access_api_detail = db_connection.access_api_col.find({"user_id": pk})
            for api_detail in access_api_detail:
                del api_detail["_id"]
                for cursor in list(dict(api_detail['warehouse_api_access']).keys()):
                    if cursor in serializer.validated_data:
                        updated_value = serializer.validated_data[cursor]
                        myquery = {"user_id": pk}
                        find_place = str('warehouse_api_access.' + cursor)
                        newvalue = {"$set": {find_place: request.data[cursor]}}
                        db_connection.access_api_col.update(myquery, newvalue)
                        data_response[f'{cursor} successfully changed to'] = updated_value

            if data_response == {}:
                db_connection.myclient.close()
                data_responses = {'message': "Data not inserted!"}
                return Response(data_responses, status=HTTP_201_CREATED)

            else:
                db_connection.myclient.close()
                data_responses = {'message': data_response}
                return Response(data_responses, status=HTTP_201_CREATED)

        else:
            db_connection.myclient.close()
            data_response = {"message": serializer.errors}
            return Response(data_response, status=HTTP_400_BAD_REQUEST)

    def get(self, request, pk):
        global data_response
        try:
            # get user access
            user_detail = db_connection.user_col.find({'user_id': pk})
            for cursor_user in user_detail:
                del cursor_user['_id']
                del cursor_user['password']
                del cursor_user['is_active']
                del cursor_user['is_admin']
                del cursor_user['last_login']
                # get app access
                access_app = db_connection.access_app_col.find({'user_id': pk})
                for cursor_app in access_app:
                    del cursor_app['_id']
                    del cursor_app['id']
                    # get api access
                    access_api = db_connection.access_api_col.find({'user_id': pk})
                    for cursor_api in access_api:
                        del cursor_api['_id']
                        del cursor_api['id']
                        data_response = {'User detail': cursor_user, 'User access to app': cursor_app,
                                         "User access to api": cursor_api}
            db_connection.myclient.close()
            return Response(data_response, status=HTTP_200_OK)
        except:
            db_connection.myclient.close()
            data_response = {'message': "User not exist"}
            return Response(data_response, status=HTTP_200_OK)

    # delete user with access
    def delete(self, request, pk):
        global username
        delete_query = {"user_id": pk}

        try:
            user = db_connection.user_col.find(delete_query)
            for cursor in user:
                username = cursor['username']
            if db_connection.user_col.find_one(delete_query):
                db_connection.user_col.delete_one(delete_query)
            if db_connection.access_api_col.find_one(delete_query):
                db_connection.access_api_col.delete_one(delete_query)
            if db_connection.access_app_col.find_one(delete_query):
                db_connection.access_app_col.delete_one(delete_query)
            data_response = f'user with this username:{username}, successfully deleted.'
            db_connection.myclient.close()
            return Response(data_response, status=HTTP_204_NO_CONTENT)

        except:
            db_connection.myclient.close()
            data_response = {'message': "User not exist!"}
            return Response(data_response, status=HTTP_200_OK)

    def get_queryset(self):
        qs = []
        return qs


# synch database for add new access to api access collection
# local action
@api_view(['GET'])
@permission_classes((AllowAny,))
def synchdb(request, format=None):
    result = db_connection.access_api_col.find()
    for cursor in result:
        del cursor['_id']
        # insert a field in an existing object})
        db_connection.access_app_col.update_one({"user_id": cursor['user_id']}, {"$set": {
            "docs_type": 2}})

        # insert a field in an existing object
        # db_connection.access_api_col.update_one({"user_id": cursor['user_id']}, {"$set": {
        #     "warehouse_api_access.warehouse_main_warehouse_handling_report": True}})

        # insert a new access object with fields
        # data_insert = {"Accounting": {"accounting_pages": [], "accounting_stocks": [{
        #     "stock_id": 1,
        #     "stock_name": "حافظ"
        # },
        #     {
        #         "stock_id": 2,
        #         "stock_name": "مشهد"
        #     }], "accounting_access": True}}
        # db_connection.access_app_col.update_one({"user_id": cursor['user_id']},
        #                                         {"$set": data_insert})
    db_connection.myclient.close()
    data_response = {'message': "All user synced"}
    return Response(data_response, status=HTTP_200_OK)


@api_view(['POST', 'GET', 'DELETE', 'PUT'])
@permission_classes((AllowAny,))
def CreateGroupAccess(request, format=None):
    # create a group
    global request_url, group_detail
    if request.method == 'POST':

        # insert api keys in group collection
        serializer = GroupSerializer(data=request.data)
        if serializer.is_valid():
            group_detail = {"group_name": request.data['group_name']}
        key_list = []
        for dict_key, dict_value in request.data.items():
            if dict_value and dict_key in serializer.validated_data:
                if dict_key == 'group_name':
                    pass
                else:
                    key_list.append(dict_key)
        group_detail['api'] = key_list

        # insert app keys in group collection
        access_serializer = AccessGroupSerializer(data=request.data)
        if access_serializer.is_valid():
            group_detail['app'] = access_serializer.validated_data
            try:
                db_connection.access_group.insert_one(group_detail)
                data_response = {'message': "Group created"}
                db_connection.myclient.close()
                return Response(data_response, status=HTTP_200_OK)
            except:
                db_connection.myclient.close()
                data_response = {'message': "something wrong!"}
                return Response(data_response, status=HTTP_200_OK)
        else:
            db_connection.myclient.close()
            data_response = {'message': access_serializer.errors}
            return Response(data_response, status=HTTP_200_OK)

    # get group names
    if request.method == 'GET':
        group_detail = db_connection.access_group.find()
        group_name = []
        for cursor in group_detail:
            group_name.append(cursor['group_name'])
        data_response = {'Existing groups are': group_name}
        db_connection.myclient.close()
        return Response(data_response, status=HTTP_200_OK)

    # delete group
    if request.method == 'DELETE':
        db_connection.access_group.delete_one({"group_name": request.data['group_name']})
        group_name = request.data['group_name']
        data_response = f'this group ({group_name}) successfully deleted'
        db_connection.myclient.close()
        return Response(data_response, status=HTTP_204_NO_CONTENT)

    # edit groups
    if request.method == 'PUT':
        group_detail = db_connection.access_group.find({"group_name": request.data['group_name']})
        request_dict = dict(request.data)
        request_dict.pop("group_name")
        keys = list(request_dict.keys())

        for cursor in group_detail:
            old_keys = cursor['keys']
            keys = keys + old_keys
        group_name = request.data['group_name']
        db_connection.access_group.update({"group_name": request.data['group_name']}, {"$set": {"keys": keys}})
        users_with_same_access = db_connection.user_col.find({"user_group": group_name})
        # request to set access to update all users with same group
        request_param = {
            "group_name": group_name
        }
        for cursor_users in users_with_same_access:
            request_url = "http://auth.aasood.com/accessgroups/" + str(cursor_users['user_id']) + "/"
            requests.put(request_url, data=json.dumps(request_param), headers={'Content-Type': 'application/json'})
        data_response = f'Group and all user with this group ({group_name}) successfully updated.'
        db_connection.myclient.close()
        return Response(data_response, status=HTTP_201_CREATED)


# set group to users and update user access
@api_view(['PUT'])
@permission_classes((AllowAny,))
def SetGruopAccess(request, pk):
    global username_response, api_access_to_assign
    try:
        group_to_assign = db_connection.access_group.find({"group_name": request.data['group_name']})
        group_response = request.data['group_name']
        user_detail = db_connection.user_col.find({"user_id": pk})
        for cursor_user in user_detail:
            username_response = cursor_user['username']
        for cursor_keys in group_to_assign:
            api_access_to_assign = cursor_keys['api']
            app_access_to_assign = dict(cursor_keys['app'])
            # Change all selected api access to true
            user_api_access = db_connection.access_api_col.find({'user_id': pk})
            for cursor_api in user_api_access:
                for key_crm in cursor_api['crm_api_access']:
                    if key_crm in api_access_to_assign:
                        set = "crm_api_access." + key_crm
                        db_connection.access_api_col.update_one({'user_id': pk}, {"$set": {set: True}})
                for key_scm in cursor_api['scm_api_access']:
                    if key_scm in api_access_to_assign:
                        set = "scm_api_access." + key_scm
                        db_connection.access_api_col.update_one({'user_id': pk}, {"$set": {set: True}})
                for key_accounting in cursor_api['accounting_api_access']:
                    if key_accounting in api_access_to_assign:
                        set = "accounting_api_access." + key_accounting
                        db_connection.access_api_col.update_one({'user_id': pk}, {"$set": {set: True}})
                for key_warehouse in cursor_api['warehouse_api_access']:
                    if key_warehouse in api_access_to_assign:
                        set = "warehouse_api_access." + key_warehouse
                        db_connection.access_api_col.update_one({'user_id': pk}, {"$set": {set: True}})

            # Change all selected app access to true
            user_app_access = db_connection.access_app_col.find({'user_id': pk})
            for cursor_app in user_app_access:

                # delete unused keys from app access array [id ,user_id, ....]
                app_access_keys = list(dict(cursor_app).keys())
                for app_cursor in range(3):
                    app_access_keys.pop(0)

                # update data base with access
                for app_keys, app_values in app_access_to_assign.items():
                    for key_cursor in app_access_keys:
                        str_keys = str(key_cursor)
                        if app_keys in cursor_app[str_keys]:
                            update_place = key_cursor + "." + app_keys
                            db_connection.access_app_col.update_one({'user_id': pk},
                                                                    {"$set": {str(update_place): app_values}})

        # set add user_group to user collection
        db_connection.user_col.update({'user_id': pk}, {"$set": {"user_group": request.data['group_name']}})
        message = f'This access ({group_response}) set for this user ({username_response})'
        data_response = {'message': message}
        db_connection.myclient.close()
        return Response(data_response, status=HTTP_200_OK)
    except:
        db_connection.myclient.close()
        data_response = {'message': "Group not exist or something wrong!"}
        return Response(data_response, status=HTTP_400_BAD_REQUEST)


# check token is valid or not
@api_view(['GET'])
@permission_classes((AllowAny,))
def TokenValidate(request, format=None):
    global access_cursor, cursor
    try:
        tokens = db_connection.token_col.find({"key": request.GET.get('token')})
        for cursor in tokens:
            access_detail = db_connection.access_app_col.find({"user_id": cursor['user_id']})
            for access_cursor in access_detail:
                del access_cursor['_id']
                del access_cursor['id']
                del access_cursor['user_id']
        user_detail = {}
        user = db_connection.user_col.find({"user_id": cursor['user_id']})
        for user_cursor in user:
            del user_cursor['_id']
            del user_cursor['password']
            del user_cursor['user_id']
            del user_cursor['last_login']
            del user_cursor['is_admin']
            del user_cursor['is_active']
            user_detail.update(user_cursor)

        token = db_connection.token_col.find({"user_id": cursor['user_id']})
        for token_cursor in token:
            del token_cursor['_id']
            del token_cursor['user_id']
            del token_cursor['created']
            user_detail.update(token_cursor)
        db_connection.myclient.close()
        data_response = {'result': {"User detail": user_detail, "Access detail": access_cursor}}
        return Response(data_response, status=HTTP_200_OK)

    except:
        db_connection.myclient.close()
        data_response = {'message': "Token not exist or invalid!'"}
        return Response(data_response, status=HTTP_400_BAD_REQUEST)


class RequestPassword(generics.GenericAPIView):
    serializer_class = ResetPasswordEmail
    permission_classes = [
        permissions.AllowAny
    ]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        # if User.objects.filter(email=email).exist():
        user_detail = db_connection.user_col.find({"email": email})
        user = User.objects.get(email=email)

        for users in user_detail:
            uidb64 = urlsafe_base64_encode(force_bytes(user.user_id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = 'auth.aasood.com'
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, "token": token})
            absurl = 'http://' + current_site + relativeLink
            email_body = 'welcome to aasood.\n Use link below to reset your password \n' + absurl
            data = {'email_body': email_body, 'to_email': [user.email], 'email_subject': 'Aasood Reset password'}
            Util.send_email(data)
        db_connection.myclient.close()
        return Response({'success': "we have sent you a link to reset your password, check junk and inbox."},
                        status=HTTP_200_OK)


class PasswordTokenCheck(generics.GenericAPIView):
    permission_classes = [
        permissions.AllowAny
    ]

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            print(id)
            user = User.objects.get(user_id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': "Token is not valid, please request a new one"},
                                status=HTTP_203_NON_AUTHORITATIVE_INFORMATION)
            return Response({'success': True, 'massage': 'Credentials valid', 'uidb64': uidb64, 'token': token},
                            status=HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': "Token is not valid, please request a new one"},
                                status=HTTP_203_NON_AUTHORITATIVE_INFORMATION)


class SetNewPassword(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    permission_classes = [
        permissions.AllowAny
    ]

    def patch(self, request):
        serlizer = self.serializer_class(data=request.data)
        serlizer.is_valid(raise_exception=True)
        return Response({"success": True, "message": "Password reset success"}, status=HTTP_200_OK)


@api_view(['POST'])
@permission_classes((AllowAny,))
def docs_add_items(request, format=None):
    data = {
        "id": request.data['id'],
        "docs_type": request.data['docsType'],
        "dataType": request.data['dataType'],
        "url": request.data['url'],
        "title": request.data['title']
    }
    data = json.dumps(data)
    type = 'post'
    content_type = 'documents'
    rpc = Get()
    mq_call = rpc.call(type, content_type, data)
    return Response(mq_call)


@api_view(['POST'])
@permission_classes((AllowAny,))
def docs_edit_items(request, format=None):
    data = {
        "userId": request.data['userId'],
        "application": request.data['application'],
        "pageName": request.data['pageName'],
        "dataType": request.data['dataType'],
        "id": request.data['id'],
        "key": request.data['key'],
        "value": request.data['value']
    }
    data = json.dumps(data)
    type = 'put'
    content_type = 'documents'
    rpc = Get()
    mq_call = rpc.call(type, content_type, data)
    return Response(mq_call)


@api_view(['POST'])
@permission_classes((AllowAny,))
def docs_delete_items(request, format=None):
    data = {
        "userId": request.data['userId'],
        "app": request.data['app'],
        "pageName": request.data['pageName'],
        "dataType": request.data['dataType'],
        "id": request.data['id'],
    }
    data = json.dumps(data)
    type = 'delete'
    content_type = 'documents'
    rpc = Get()
    mq_call = rpc.call(type, content_type, data)
    return Response(mq_call)

@api_view(['GET'])
@permission_classes((AllowAny,))
def docs_get_items(request, format=None):
    data = {
        "userId": request.GET.get('userId'),
    }
    data = json.dumps(data)
    type = 'get'
    content_type = 'documents'
    rpc = Get()
    mq_call = rpc.call(type, content_type, data)
    return Response(mq_call)