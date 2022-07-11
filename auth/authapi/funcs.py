from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST
from .config import db_connection


class set_access():
    def set_access_view(pk):
        user_detail = {"user_id": pk, "id": pk,
                       "Wms": {"wms_access": False, "wms_pages": [], "wms_stockid": [], "documents": False,
                               "docs_id": 1},
                       "Crm": {"crm_access": False, "crm_pages": [], "crm_stockid": [], "documents": False,
                               "docs_id": 3},
                       "Catalog": {"catalog_access": False, "catalog_pages": [], "catalog_stockid": [],
                                   "documents": False, "docs_id": 4},
                       "Accounting": {"acoounting_access": False, "acoounting_pages": [], "acoounting_stockid": [],
                                      "documents": False, "docs_id": 5},
                       "SCM": {"scm_access": False, "scm_pages": [], "scm_stockid": [], "documents": False,
                               "docs_id": 2},
                       "Logistic": {"logistic_access": False, "logistic_pages": [], "logistic_stockid": [],
                                    "documents": False, "docs_id": 6},
                       "Marketplace": {"marketplace_access": False, "marketplace_pages": [], "seller": [],
                                       "documents": False, "docs_id": 7}
                       }
        db_connection.access_app_col.insert_one(user_detail)
        try:
            first_access_detail = {"user_id": pk, "id": pk, }
            db_connection.access_api_col.insert_one(first_access_detail)
            # copy all access from admin user
            find_access = db_connection.access_api_col.find({"user_id": 1})
            # Get keys from existing access collection and insert to new user
            for detail in find_access:
                del detail["_id"]
                del detail["id"]
                del detail["user_id"]

                for cursor in list(dict(detail['crm_api_access']).keys()):
                    go_to_object = str("crm_api_access." + cursor)
                    db_connection.access_api_col.update_one({"user_id": pk}, {"$set": {go_to_object: False}})

                for cursor in list(dict(detail['scm_api_access']).keys()):
                    go_to_object = str("scm_api_access." + cursor)
                    db_connection.access_api_col.update_one({"user_id": pk}, {"$set": {go_to_object: False}})

                for cursor in list(dict(detail['accounting_api_access']).keys()):
                    go_to_object = str("accounting_api_access." + cursor)
                    db_connection.access_api_col.update_one({"user_id": pk}, {"$set": {go_to_object: False}})

                for cursor in list(dict(detail['warehouse_api_access']).keys()):
                    go_to_object = str("warehouse_api_access." + cursor)
                    db_connection.access_api_col.update_one({"user_id": pk}, {"$set": {go_to_object: False}})
            db_connection.myclient.close()

        except:
            db_connection.myclient.close()
            data_response = {"message": "Something wrong! call support."}
            return Response(data_response, status=HTTP_400_BAD_REQUEST)


class Groups:
    def __init__(self):
        self.access_to_assign = None
        self.cursor_keys = None
        self.cursor_assigned = None

    def set_user_group(self, pk, group_name):
        group_to_assign = db_connection.access_group.find({"group_name": group_name})
        for cursor_keys in group_to_assign:
            access_to_assign = cursor_keys['keys']

        # Change all selected access to true
        find_user = db_connection.access_api_col.find({'user_id': pk})
        for cursor in find_user:
            for key in cursor['crm_api_access']:
                if key in self.access_to_assign:
                    set = "crm_api_access." + key
                    db_connection.access_api_col.update_one({'user_id': pk}, {"$set": {set: True}})

        # save assigned user id
        users_to_add = []
        for cursor_assigned in self.cursor_keys['users_assigned']:
            if pk == cursor_assigned:
                break
            else:
                users_to_add.append(pk)
                break
        self.cursor_assigned.extend(self.cursor_keys['users_assigned'])

        db_connection.access_group.update({"group_name": group_name},
                                          {"$set": {"users_assigned": self.cursor_assigned}})

        return
