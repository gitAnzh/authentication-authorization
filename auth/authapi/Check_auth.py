import json

import requests
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response


def check_auth(func):
    def wrapper(request, *args, **kwargs):

        # request
        param = {
            "key": request.headers['Authorization'],
            "api": func.__name__
        }
        req = requests.post("http://auth.aasood.com/check/", data=json.dumps(param),
                            headers={'Content-Type': 'application/json'})
        data = json.loads(req.content)
        if data['message'] == True:
            return func(request, *args, **kwargs)
        else:
            response_auth = Response(
                {'message': 'You do not have permission! call support.'},
                content_type="application/json",
                status=status.HTTP_203_NON_AUTHORITATIVE_INFORMATION
            )
            response_auth.accepted_renderer = JSONRenderer()
            response_auth.accepted_media_type = "application/json"
            response_auth.renderer_context = {}

            return response_auth

    return wrapper