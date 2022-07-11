from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt

from .views import LoginUserView, RegisterUserView, ChangePasswordView, CheckToken, EditUserView, synchdb, \
    SetGruopAccess, CreateGroupAccess, TokenValidate, LoginMarketplace, PasswordTokenCheck, RequestPassword, \
    SetNewPassword, docs_get_items, docs_delete_items, docs_edit_items, docs_add_items

urlpatterns = [
    path('signup/', RegisterUserView),
    path('login/', LoginUserView),
    path('changepassword/', csrf_exempt(ChangePasswordView.as_view())),
    path('', include('djoser.urls.authtoken')),
    path('check/', CheckToken),
    path('edituser/<int:pk>/', csrf_exempt(EditUserView.as_view())),
    path('synchdb/', csrf_exempt(synchdb)),
    path('creategroup/', csrf_exempt(CreateGroupAccess)),
    path('accessgroups/<int:pk>/', csrf_exempt(SetGruopAccess)),
    path('token/', csrf_exempt(TokenValidate)),
    path('marketplace/', csrf_exempt(LoginMarketplace)),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheck.as_view(), name='password-reset-confirm'),
    path('requst-reset-email/', csrf_exempt(RequestPassword.as_view()), name='requst-reset-email'),
    path('password-reset-complete/', csrf_exempt(SetNewPassword.as_view()), name='password-reset-complete'),
    path('get_docs/', docs_get_items),
    path('delete_docs/', docs_delete_items),
    path('edit_docs/', docs_edit_items),
    path('add_docs/', docs_add_items),

]
