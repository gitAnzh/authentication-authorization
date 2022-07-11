from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from .models import User


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(style={'input_type': 'password', 'placeholder': 'Password'}, required=True)

    def validate(self, data):
        username = data['username']
        if not 'username' in data:
            raise serializers.ValidationError('Enter Username ')
        return data


class RegisterSerializers(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(style={'input_type': 'password', 'placeholder': 'Password'}, required=True)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    usertype = serializers.IntegerField(required=False)
    is_admin = serializers.BooleanField(required=False, default=False)
    is_marketplace = serializers.BooleanField(required=False, default=False)

    def validate(self, data):
        email = data['email']
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('Email Already Exist')
        if 'username' in data:
            username = data['username']
            if User.objects.filter(username=username).exists():
                raise serializers.ValidationError('Username Already Exist')
        return data


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(style={'input_type': 'password', 'placeholder': 'Password'})
    new_password = serializers.CharField(style={'input_type': 'password', 'placeholder': 'Password'})
    renew_password = serializers.CharField(style={'input_type': 'password', 'placeholder': 'Password'})


class TokenSerializer(serializers.Serializer):
    key = serializers.CharField(required=True)
    api = serializers.CharField(required=True)


class EditUserSerializer(serializers.Serializer):
    # user collection
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    usertype = serializers.IntegerField(required=False)
    is_marketplace = serializers.BooleanField(required=False)
    # app access
    wms_access = serializers.BooleanField(required=False)
    wms_pages = serializers.ListField(required=False)
    wms_stockid = serializers.ListField(required=False)
    crm_access = serializers.BooleanField(required=False)
    crm_pages = serializers.ListField(required=False)
    access_supplyf = serializers.BooleanField(required=False)
    scm_pages = serializers.ListField(required=False)
    scm_access = serializers.BooleanField(required=False)
    accounting_access = serializers.BooleanField(required=False)
    accounting_pages = serializers.ListField(required=False)
    catalog_access = serializers.BooleanField(required=False)
    catalog_pages = serializers.ListField(required=False)
    log_pages = serializers.ListField(required=False)
    log_access = serializers.BooleanField(required=False)
    marketplace_access = serializers.BooleanField(required=False)
    marketplace_pages = serializers.ListField(required=False)
    seller = serializers.ListField(required=False)
    # api access
    crm_customerprofile_get_statestatus = serializers.BooleanField(required=False)
    crm_customerprofile_get_regionstatus = serializers.BooleanField(required=False)
    crm_customerprofile_get_totalstatus = serializers.BooleanField(required=False)
    crm_customerprofile_get_qtygrid = serializers.BooleanField(required=False)
    crm_customerprofile_get_customerpromotionslist = serializers.BooleanField(required=False)
    crm_customerprofile_get_promotionslist = serializers.BooleanField(required=False)
    crm_customerprofile_put_updatepromotions = serializers.BooleanField(required=False)
    crm_customerprofile_post_insterpromotions = serializers.BooleanField(required=False)
    crm_customerprofile_get_stateqtydashboard = serializers.BooleanField(required=False)
    crm_customerprofile_get_regionqtydashboard = serializers.BooleanField(required=False)
    crm_customerprofile_get_getorders = serializers.BooleanField(required=False)
    crm_customerprofile_get_customerperformance = serializers.BooleanField(required=False)
    crm_customerprofile_get_customerorder = serializers.BooleanField(required=False)
    crm_customerprofile_get_customerlist = serializers.BooleanField(required=False)
    crm_call_get_agent = serializers.BooleanField(required=False)
    crm_call_get_descriptionsticket = serializers.BooleanField(required=False)
    crm_call_post_descriptionticket = serializers.BooleanField(required=False)
    crm_call_get_relatedtickets = serializers.BooleanField(required=False)
    crm_call_get_ticketslist = serializers.BooleanField(required=False)
    crm_call_post_agent = serializers.BooleanField(required=False)
    crm_call_post_ticket = serializers.BooleanField(required=False)
    crm_call_get_calldata = serializers.BooleanField(required=False)
    crm_ticket_get_agent = serializers.BooleanField(required=False)
    crm_ticket_post_agent = serializers.BooleanField(required=False)
    crm_ticket_get_department = serializers.BooleanField(required=False)
    crm_ticket_post_department = serializers.BooleanField(required=False)
    crm_ticket_post_mainticketoptions = serializers.BooleanField(required=False)
    crm_ticket_insert_subsidiaryticketoptions = serializers.BooleanField(required=False)
    crm_ticket_post_status = serializers.BooleanField(required=False)
    crm_ticket_get_ticketlist = serializers.BooleanField(required=False)
    crm_ticket_get_relatedtickets = serializers.BooleanField(required=False)
    crm_ticket_post_ticket = serializers.BooleanField(required=False)
    crm_ticket_put_ticket = serializers.BooleanField(required=False)
    crm_ticket_get_filters = serializers.BooleanField(required=False)
    crm_customerprofile_get_magentoorders = serializers.BooleanField(required=False)
    crm_ticket_get_mainticketoptions = serializers.BooleanField(required=False)
    crm_ticket_get_subsidiaryticketoptions = serializers.BooleanField(required=False)
    crm_customerprofile_update_magentoorders = serializers.BooleanField(required=False)
    crm_customerprofile_filter_magentoorders = serializers.BooleanField(required=False)
    crm_customerprofile_put_returnproduct = serializers.BooleanField(required=False)
    crm_customerprofile_get_returnproduct = serializers.BooleanField(required=False)

    scm_buying_post_buyingorder = serializers.BooleanField(required=False)
    scm_buying_get_formbyid = serializers.BooleanField(required=False)
    scm_buying_get_presubmit = serializers.BooleanField(required=False)
    scm_buying_get_submit = serializers.BooleanField(required=False)
    scm_buying_get_logistic = serializers.BooleanField(required=False)
    scm_buying_get_wms = serializers.BooleanField(required=False)
    scm_buying_get_all = serializers.BooleanField(required=False)
    scm_buying_put_buyingaccounting = serializers.BooleanField(required=False)
    scm_buying_put_db = serializers.BooleanField(required=False)
    scm_storedform_post_borrowingform = serializers.BooleanField(required=False)
    scm_storedform_get_borrowingform = serializers.BooleanField(required=False)
    scm_storedform_get_borrowinglist = serializers.BooleanField(required=False)
    scm_storedform_put_borrowingform = serializers.BooleanField(required=False)
    scm_supplier_post_supplier = serializers.BooleanField(required=False)
    scm_supplier_get_supplier = serializers.BooleanField(required=False)
    scm_supplier_get_allsuppliers = serializers.BooleanField(required=False)
    scm_supplier_get_activesuppliers = serializers.BooleanField(required=False)
    scm_supplier_get_supplierperformance = serializers.BooleanField(required=False)
    scm_supplier_put_updatesupplier = serializers.BooleanField(required=False)
    scm_supplier_delete_supplier = serializers.BooleanField(required=False)
    scm_supplier_delete_address = serializers.BooleanField(required=False)
    scm_supplier_put_supplierdb = serializers.BooleanField(required=False)
    scm_supplier_put_insertaddress = serializers.BooleanField(required=False)
    scm_transferform_post_transfer_form = serializers.BooleanField(required=False)
    scm_transferform_get_transferform = serializers.BooleanField(required=False)
    scm_transferform_get_alltransferforms = serializers.BooleanField(required=False)
    scm_transferform_put_transferform = serializers.BooleanField(required=False)
    scm_supplier_post_supplier_variety = serializers.BooleanField(required=False)

    warehouse_multystock_put_warehouse = serializers.BooleanField(required=False)
    warehouse_multystock_post_warehouse = serializers.BooleanField(required=False)
    warehouse_multystock_get_allwarehouses = serializers.BooleanField(required=False)
    warehouse_multystock_get_warehouse = serializers.BooleanField(required=False)
    warehouse_main_post_newproduct = serializers.BooleanField(required=False)
    warehouse_main_get_processing = serializers.BooleanField(required=False)
    warehouse_main_get_inwarehouse = serializers.BooleanField(required=False)
    warehouse_main_get_complete = serializers.BooleanField(required=False)
    warehouse_main_put_warehouse = serializers.BooleanField(required=False)
    warehouse_main_get_warehouse = serializers.BooleanField(required=False)
    warehouse_main_get_checkingwarehouse = serializers.BooleanField(required=False)
    warehouse_main_post_exitwarehouse = serializers.BooleanField(required=False)
    warehouse_main_get_products = serializers.BooleanField(required=False)
    warehouse_main_get_total_product = serializers.BooleanField(required=False)
    warehouse_main_get_shiped = serializers.BooleanField(required=False)
    warehouse_main_get_wms_report = serializers.BooleanField(required=False)
    warehouse_main_get_shiped_list = serializers.BooleanField(required=False)
    warehouse_main_get_fullcomplete = serializers.BooleanField(required=False)
    warehouse_main_get_checking_export_transfer = serializers.BooleanField(required=False)
    warehouse_main_export_transfer = serializers.BooleanField(required=False)
    warehouse_main_get_referral_catalog = serializers.BooleanField(required=False)
    warehouse_main_get_checking_import_transfer = serializers.BooleanField(required=False)
    warehouse_main_import_transfer = serializers.BooleanField(required=False)
    warehouse_main_warehouse_handling = serializers.BooleanField(required=False)
    warehouse_main_warehouse_handling_report = serializers.BooleanField(required=False)

    kosar_post_PushOrder = serializers.BooleanField(required=False)
    kosar_get_alldetail = serializers.BooleanField(required=False)
    kosar_put_order = serializers.BooleanField(required=False)
    accounting_get_customerlist = serializers.BooleanField(required=False)


class GroupSerializer(serializers.Serializer):
    group_name = serializers.CharField(required=True)
    crm_customerprofile_get_statestatus = serializers.BooleanField(required=False)
    crm_customerprofile_get_regionstatus = serializers.BooleanField(required=False)
    crm_customerprofile_get_totalstatus = serializers.BooleanField(required=False)
    crm_customerprofile_get_qtygrid = serializers.BooleanField(required=False)
    crm_customerprofile_get_customerpromotionslist = serializers.BooleanField(required=False)
    crm_customerprofile_get_promotionslist = serializers.BooleanField(required=False)
    crm_customerprofile_put_updatepromotions = serializers.BooleanField(required=False)
    crm_customerprofile_post_insterpromotions = serializers.BooleanField(required=False)
    crm_customerprofile_get_stateqtydashboard = serializers.BooleanField(required=False)
    crm_customerprofile_get_regionqtydashboard = serializers.BooleanField(required=False)
    crm_customerprofile_get_getorders = serializers.BooleanField(required=False)
    crm_customerprofile_get_customerperformance = serializers.BooleanField(required=False)
    crm_customerprofile_get_customerorder = serializers.BooleanField(required=False)
    crm_customerprofile_get_customerlist = serializers.BooleanField(required=False)
    crm_call_get_agent = serializers.BooleanField(required=False)
    crm_call_get_descriptionsticket = serializers.BooleanField(required=False)
    crm_call_post_descriptionticket = serializers.BooleanField(required=False)
    crm_call_get_relatedtickets = serializers.BooleanField(required=False)
    crm_call_get_ticketslist = serializers.BooleanField(required=False)
    crm_call_post_agent = serializers.BooleanField(required=False)
    crm_call_post_ticket = serializers.BooleanField(required=False)
    crm_call_get_calldata = serializers.BooleanField(required=False)
    crm_ticket_get_agent = serializers.BooleanField(required=False)
    crm_ticket_post_agent = serializers.BooleanField(required=False)
    crm_ticket_get_department = serializers.BooleanField(required=False)
    crm_ticket_post_department = serializers.BooleanField(required=False)
    crm_ticket_post_mainticketoptions = serializers.BooleanField(required=False)
    crm_ticket_insert_subsidiaryticketoptions = serializers.BooleanField(required=False)
    crm_ticket_post_status = serializers.BooleanField(required=False)
    crm_ticket_get_ticketlist = serializers.BooleanField(required=False)
    crm_ticket_get_relatedtickets = serializers.BooleanField(required=False)
    crm_ticket_post_ticket = serializers.BooleanField(required=False)
    crm_ticket_put_ticket = serializers.BooleanField(required=False)
    crm_ticket_get_filters = serializers.BooleanField(required=False)
    crm_customerprofile_get_magentoorders = serializers.BooleanField(required=False)
    crm_ticket_get_mainticketoptions = serializers.BooleanField(required=False)
    crm_ticket_get_subsidiaryticketoptions = serializers.BooleanField(required=False)
    crm_customerprofile_update_magentoorders = serializers.BooleanField(required=False)
    crm_customerprofile_filter_magentoorders = serializers.BooleanField(required=False)
    crm_customerprofile_put_returnproduct = serializers.BooleanField(required=False)
    crm_customerprofile_get_returnproduct = serializers.BooleanField(required=False)

    scm_buying_post_buyingorder = serializers.BooleanField(required=False)
    scm_buying_get_formbyid = serializers.BooleanField(required=False)
    scm_buying_get_presubmit = serializers.BooleanField(required=False)
    scm_buying_get_submit = serializers.BooleanField(required=False)
    scm_buying_get_logistic = serializers.BooleanField(required=False)
    scm_buying_get_wms = serializers.BooleanField(required=False)
    scm_buying_get_all = serializers.BooleanField(required=False)
    scm_buying_put_buyingaccounting = serializers.BooleanField(required=False)
    scm_buying_put_db = serializers.BooleanField(required=False)
    scm_storedform_post_borrowingform = serializers.BooleanField(required=False)
    scm_storedform_get_borrowingform = serializers.BooleanField(required=False)
    scm_storedform_get_borrowinglist = serializers.BooleanField(required=False)
    scm_storedform_put_borrowingform = serializers.BooleanField(required=False)
    scm_supplier_post_supplier = serializers.BooleanField(required=False)
    scm_supplier_get_supplier = serializers.BooleanField(required=False)
    scm_supplier_get_allsuppliers = serializers.BooleanField(required=False)
    scm_supplier_get_activesuppliers = serializers.BooleanField(required=False)
    scm_supplier_get_supplierperformance = serializers.BooleanField(required=False)
    scm_supplier_put_updatesupplier = serializers.BooleanField(required=False)
    scm_supplier_delete_supplier = serializers.BooleanField(required=False)
    scm_supplier_delete_address = serializers.BooleanField(required=False)
    scm_supplier_put_supplierdb = serializers.BooleanField(required=False)
    scm_supplier_put_insertaddress = serializers.BooleanField(required=False)
    scm_transferform_post_transfer_form = serializers.BooleanField(required=False)
    scm_transferform_get_transferform = serializers.BooleanField(required=False)
    scm_transferform_get_alltransferforms = serializers.BooleanField(required=False)
    scm_transferform_put_transferform = serializers.BooleanField(required=False)
    scm_supplier_post_supplier_variety = serializers.BooleanField(required=False)

    warehouse_multystock_put_warehouse = serializers.BooleanField(required=False)
    warehouse_multystock_post_warehouse = serializers.BooleanField(required=False)
    warehouse_multystock_get_allwarehouses = serializers.BooleanField(required=False)
    warehouse_multystock_get_warehouse = serializers.BooleanField(required=False)
    warehouse_main_post_newproduct = serializers.BooleanField(required=False)
    warehouse_main_get_processing = serializers.BooleanField(required=False)
    warehouse_main_get_inwarehouse = serializers.BooleanField(required=False)
    warehouse_main_get_complete = serializers.BooleanField(required=False)
    warehouse_main_put_warehouse = serializers.BooleanField(required=False)
    warehouse_main_get_warehouse = serializers.BooleanField(required=False)
    warehouse_main_get_checkingwarehouse = serializers.BooleanField(required=False)
    warehouse_main_post_exitwarehouse = serializers.BooleanField(required=False)
    warehouse_main_get_products = serializers.BooleanField(required=False)
    warehouse_main_get_total_product = serializers.BooleanField(required=False)
    warehouse_main_get_shiped = serializers.BooleanField(required=False)
    warehouse_main_get_wms_report = serializers.BooleanField(required=False)
    warehouse_main_get_shiped_list = serializers.BooleanField(required=False)
    warehouse_main_get_fullcomplete = serializers.BooleanField(required=False)
    warehouse_main_get_checking_export_transfer = serializers.BooleanField(required=False)
    warehouse_main_export_transfer = serializers.BooleanField(required=False)
    warehouse_main_get_referral_catalog = serializers.BooleanField(required=False)
    warehouse_main_get_checking_import_transfer = serializers.BooleanField(required=False)
    warehouse_main_import_transfer = serializers.BooleanField(required=False)
    warehouse_main_warehouse_handling = serializers.BooleanField(required=False)
    warehouse_main_warehouse_handling_report = serializers.BooleanField(required=False)

    kosar_post_PushOrder = serializers.BooleanField(required=False)
    kosar_get_alldetail = serializers.BooleanField(required=False)
    kosar_put_order = serializers.BooleanField(required=False)
    accounting_get_customerlist = serializers.BooleanField(required=False)


class AccessGroupSerializer(serializers.Serializer):
    # app access
    wms_access = serializers.BooleanField(required=False)
    wms_pages = serializers.ListField(required=False)
    wms_stockid = serializers.ListField(required=False)
    crm_access = serializers.BooleanField(required=False)
    crm_pages = serializers.ListField(required=False)
    access_supplyf = serializers.BooleanField(required=False)
    scm_pages = serializers.ListField(required=False)
    scm_access = serializers.BooleanField(required=False)
    accounting_access = serializers.BooleanField(required=False)
    accounting_pages = serializers.ListField(required=False)
    catalog_access = serializers.BooleanField(required=False)
    catalog_pages = serializers.ListField(required=False)
    log_pages = serializers.ListField(required=False)
    log_access = serializers.BooleanField(required=False)
    marketplace_access = serializers.BooleanField(required=False)
    marketplace_pages = serializers.ListField(required=False)
    seller = serializers.ListField(required=False)


class ResetPasswordEmail(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uibd64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uibd64))
            user = User.objects.get(user_id=id)
            user.set_password(password)
            user.save()
            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid!', 401)


