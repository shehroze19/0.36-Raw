import base64
import datetime
import json
import logging
import re
from typing import Dict, List, Set

from flask import g, session, url_for
from flask_babel import lazy_gettext as _
from flask_jwt_extended import current_user as current_user_jwt
from flask_jwt_extended import JWTManager
from flask_login import current_user, LoginManager
from flask_openid import OpenID
from werkzeug.security import check_password_hash, generate_password_hash

from .api import SecurityApi
from .registerviews import (
    RegisterUserDBView,
    RegisterUserOAuthView,
    RegisterUserOIDView,
)
from .views import (
    AuthDBView,
    AuthLDAPView,
    AuthOAuthView,
    AuthOIDView,
    AuthRemoteUserView,
    PermissionModelView,
    PermissionViewModelView,
    RegisterUserModelView,
    ResetMyPasswordView,
    ResetPasswordView,
    RoleModelView,
    UserDBModelView,
    UserInfoEditView,
    UserLDAPModelView,
    UserOAuthModelView,
    UserOIDModelView,
    UserRemoteUserModelView,
    UserStatsChartView,
    ViewMenuModelView,
)
from ..basemanager import BaseManager
from ..const import (
    AUTH_DB,
    AUTH_LDAP,
    AUTH_OAUTH,
    AUTH_OID,
    AUTH_REMOTE_USER,
    LOGMSG_ERR_SEC_AUTH_LDAP,
    LOGMSG_ERR_SEC_AUTH_LDAP_TLS,
    LOGMSG_WAR_SEC_LOGIN_FAILED,
    LOGMSG_WAR_SEC_NO_USER,
    LOGMSG_WAR_SEC_NOLDAP_OBJ,
    PERMISSION_PREFIX,
)

log = logging.getLogger(__name__)


class AbstractSecurityManager(BaseManager):
    """
        Abstract SecurityManager class, declares all methods used by the
        framework. There is no assumptions about security models or auth types.
    """

    def add_permissions_view(self, base_permissions, view_menu):
        """
            Adds a permission on a view menu to the backend

            :param base_permissions:
                list of permissions from view (all exposed methods):
                 'can_add','can_edit' etc...
            :param view_menu:
                name of the view or menu to add
        """
        raise NotImplementedError

    def add_permissions_menu(self, view_menu_name):
        """
            Adds menu_access to menu on permission_view_menu

            :param view_menu_name:
                The menu name
        """
        raise NotImplementedError

    def register_views(self):
        """
            Generic function to create the security views
        """
        raise NotImplementedError

    def is_item_public(self, permission_name, view_name):
        """
            Check if view has public permissions

            :param permission_name:
                the permission: can_show, can_edit...
            :param view_name:
                the name of the class view (child of BaseView)
        """
        raise NotImplementedError

    def has_access(self, permission_name, view_name):
        """
            Check if current user or public has access to view or menu
        """
        raise NotImplementedError

    def security_cleanup(self, baseviews, menus):
        raise NotImplementedError


def _oauth_tokengetter(token=None):
    """
        Default function to return the current user oauth token
        from session cookie.
    """
    token = session.get("oauth")
    log.debug("Token Get: {0}".format(token))
    return token


class BaseSecurityManager(AbstractSecurityManager):
    auth_view = None
    """ The obj instance for authentication view """
    user_view = None
    """ The obj instance for user view """
    registeruser_view = None
    """ The obj instance for registering user view """
    lm = None
    """ Flask-Login LoginManager """
    jwt_manager = None
    """ Flask-JWT-Extended """
    oid = None
    """ Flask-OpenID OpenID """
    oauth = None
    """ Flask-OAuth """
    oauth_remotes = None
    """ OAuth email whitelists """
    oauth_whitelists = {}
    """ Initialized (remote_app) providers dict {'provider_name', OBJ } """
    oauth_tokengetter = _oauth_tokengetter
    """ OAuth tokengetter function override to implement your own tokengetter method """
    oauth_user_info = None

    user_model = None
    """ Override to set your own User Model """
    role_model = None
    """ Override to set your own Role Model """
    permission_model = None
    """ Override to set your own Permission Model """
    viewmenu_model = None
    """ Override to set your own ViewMenu Model """
    permissionview_model = None
    """ Override to set your own PermissionView Model """
    registeruser_model = None
    """ Override to set your own RegisterUser Model """

    userdbmodelview = UserDBModelView
    """ Override if you want your own user db view """
    userldapmodelview = UserLDAPModelView
    """ Override if you want your own user ldap view """
    useroidmodelview = UserOIDModelView
    """ Override if you want your own user OID view """
    useroauthmodelview = UserOAuthModelView
    """ Override if you want your own user OAuth view """
    userremoteusermodelview = UserRemoteUserModelView
    """ Override if you want your own user REMOTE_USER view """
    registerusermodelview = RegisterUserModelView

    authdbview = AuthDBView
    """ Override if you want your own Authentication DB view """
    authldapview = AuthLDAPView
    """ Override if you want your own Authentication LDAP view """
    authoidview = AuthOIDView
    """ Override if you want your own Authentication OID view """
    authoauthview = AuthOAuthView
    """ Override if you want your own Authentication OAuth view """
    authremoteuserview = AuthRemoteUserView
    """ Override if you want your own Authentication REMOTE_USER view """

    registeruserdbview = RegisterUserDBView
    """ Override if you want your own register user db view """
    registeruseroidview = RegisterUserOIDView
    """ Override if you want your own register user OpenID view """
    registeruseroauthview = RegisterUserOAuthView
    """ Override if you want your own register user OAuth view """

    resetmypasswordview = ResetMyPasswordView
    """ Override if you want your own reset my password view """
    resetpasswordview = ResetPasswordView
    """ Override if you want your own reset password view """
    userinfoeditview = UserInfoEditView
    """ Override if you want your own User information edit view """

    # API
    security_api = SecurityApi
    """ Override if you want your own Security API login endpoint """

    rolemodelview = RoleModelView
    permissionmodelview = PermissionModelView
    userstatschartview = UserStatsChartView
    viewmenumodelview = ViewMenuModelView
    permissionviewmodelview = PermissionViewModelView

    def __init__(self, appbuilder):
        super(BaseSecurityManager, self).__init__(appbuilder)
        app = self.appbuilder.get_app
        # Base Security Config
        app.config.setdefault("AUTH_ROLE_ADMIN", "Admin")
        app.config.setdefault("AUTH_ROLE_PUBLIC", "Public")
        app.config.setdefault("AUTH_TYPE", AUTH_DB)
        # Self Registration
        app.config.setdefault("AUTH_USER_REGISTRATION", False)
        app.config.setdefault("AUTH_USER_REGISTRATION_ROLE", self.auth_role_public)

        # LDAP Config
        if self.auth_type == AUTH_LDAP:
            if "AUTH_LDAP_SERVER" not in app.config:
                raise Exception(
                    "No AUTH_LDAP_SERVER defined on config"
                    " with AUTH_LDAP authentication type."
                )
            app.config.setdefault("AUTH_LDAP_SEARCH", "")
            app.config.setdefault("AUTH_LDAP_SEARCH_FILTER", "")
            app.config.setdefault("AUTH_LDAP_BIND_USER", "")
            app.config.setdefault("AUTH_LDAP_APPEND_DOMAIN", "")
            app.config.setdefault("AUTH_LDAP_USERNAME_FORMAT", "")
            app.config.setdefault("AUTH_LDAP_BIND_PASSWORD", "")
            # TLS options
            app.config.setdefault("AUTH_LDAP_USE_TLS", False)
            app.config.setdefault("AUTH_LDAP_ALLOW_SELF_SIGNED", False)
            app.config.setdefault("AUTH_LDAP_TLS_DEMAND", False)
            app.config.setdefault("AUTH_LDAP_TLS_CACERTDIR", "")
            app.config.setdefault("AUTH_LDAP_TLS_CACERTFILE", "")
            app.config.setdefault("AUTH_LDAP_TLS_CERTFILE", "")
            app.config.setdefault("AUTH_LDAP_TLS_KEYFILE", "")
            # Mapping options
            app.config.setdefault("AUTH_LDAP_UID_FIELD", "uid")
            app.config.setdefault("AUTH_LDAP_FIRSTNAME_FIELD", "givenName")
            app.config.setdefault("AUTH_LDAP_LASTNAME_FIELD", "sn")
            app.config.setdefault("AUTH_LDAP_EMAIL_FIELD", "mail")

        if self.auth_type == AUTH_OID:
            self.oid = OpenID(app)
        if self.auth_type == AUTH_OAUTH:
            from flask_oauthlib.client import OAuth

            self.oauth = OAuth()
            self.oauth_remotes = dict()
            for _provider in self.oauth_providers:
                provider_name = _provider["name"]
                log.debug("OAuth providers init {0}".format(provider_name))
                obj_provider = self.oauth.remote_app(
                    provider_name, **_provider["remote_app"]
                )
                obj_provider._tokengetter = self.oauth_tokengetter
                if not self.oauth_user_info:
                    self.oauth_user_info = self.get_oauth_user_info
                # Whitelist only users with matching emails
                if "whitelist" in _provider:
                    self.oauth_whitelists[provider_name] = _provider["whitelist"]
                self.oauth_remotes[provider_name] = obj_provider

        self._builtin_roles = self.create_builtin_roles()
        # Setup Flask-Login
        self.lm = self.create_login_manager(app)

        # Setup Flask-Jwt-Extended
        self.jwt_manager = self.create_jwt_manager(app)

    def create_login_manager(self, app) -> LoginManager:
        """
            Override to implement your custom login manager instance

            :param app: Flask app
        """
        lm = LoginManager(app)
        lm.login_view = "login"
        lm.user_loader(self.load_user)
        return lm

    def create_jwt_manager(self, app) -> JWTManager:
        """
            Override to implement your custom JWT manager instance

            :param app: Flask app
        """
        jwt_manager = JWTManager()
        jwt_manager.init_app(app)
        jwt_manager.user_loader_callback_loader(self.load_user_jwt)
        return jwt_manager

    def create_builtin_roles(self):
        return self.appbuilder.get_app.config.get("FAB_ROLES", {})

    @property
    def get_url_for_registeruser(self):
        return url_for(
            "%s.%s"
            % (self.registeruser_view.endpoint, self.registeruser_view.default_view)
        )

    @property
    def get_user_datamodel(self):
        return self.user_view.datamodel

    @property
    def get_register_user_datamodel(self):
        return self.registerusermodelview.datamodel

    @property
    def builtin_roles(self):
        return self._builtin_roles

    @property
    def auth_type(self):
        return self.appbuilder.get_app.config["AUTH_TYPE"]

    @property
    def auth_username_ci(self):
        return self.appbuilder.get_app.config.get("AUTH_USERNAME_CI", True)

    @property
    def auth_role_admin(self):
        return self.appbuilder.get_app.config["AUTH_ROLE_ADMIN"]

    @property
    def auth_role_public(self):
        return self.appbuilder.get_app.config["AUTH_ROLE_PUBLIC"]

    @property
    def auth_ldap_server(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_SERVER"]

    @property
    def auth_ldap_use_tls(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_USE_TLS"]

    @property
    def auth_user_registration(self):
        return self.appbuilder.get_app.config["AUTH_USER_REGISTRATION"]

    @property
    def auth_user_registration_role(self):
        return self.appbuilder.get_app.config["AUTH_USER_REGISTRATION_ROLE"]

    @property
    def auth_ldap_search(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_SEARCH"]

    @property
    def auth_ldap_search_filter(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_SEARCH_FILTER"]

    @property
    def auth_ldap_bind_user(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_BIND_USER"]

    @property
    def auth_ldap_bind_password(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_BIND_PASSWORD"]

    @property
    def auth_ldap_append_domain(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_APPEND_DOMAIN"]

    @property
    def auth_ldap_username_format(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_USERNAME_FORMAT"]

    @property
    def auth_ldap_uid_field(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_UID_FIELD"]

    @property
    def auth_ldap_firstname_field(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_FIRSTNAME_FIELD"]

    @property
    def auth_ldap_lastname_field(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_LASTNAME_FIELD"]

    @property
    def auth_ldap_email_field(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_EMAIL_FIELD"]

    @property
    def auth_ldap_bind_first(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_BIND_FIRST"]

    @property
    def auth_ldap_allow_self_signed(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_ALLOW_SELF_SIGNED"]

    @property
    def auth_ldap_tls_demand(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_TLS_DEMAND"]

    @property
    def auth_ldap_tls_cacertdir(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_TLS_CACERTDIR"]

    @property
    def auth_ldap_tls_cacertfile(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_TLS_CACERTFILE"]

    @property
    def auth_ldap_tls_certfile(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_TLS_CERTFILE"]

    @property
    def auth_ldap_tls_keyfile(self):
        return self.appbuilder.get_app.config["AUTH_LDAP_TLS_KEYFILE"]

    @property
    def openid_providers(self):
        return self.appbuilder.get_app.config["OPENID_PROVIDERS"]

    @property
    def oauth_providers(self):
        return self.appbuilder.get_app.config["OAUTH_PROVIDERS"]

    @property
    def current_user(self):
        if current_user.is_authenticated:
            return g.user
        elif current_user_jwt:
            return current_user_jwt

    def oauth_user_info_getter(self, f):
        """
            Decorator function to be the OAuth user info getter
            for all the providers, receives provider and response
            return a dict with the information returned from the provider.
            The returned user info dict should have it's keys with the same
            name as the User Model.

            Use it like this an example for GitHub ::

                @appbuilder.sm.oauth_user_info_getter
                def my_oauth_user_info(sm, provider, response=None):
                    if provider == 'github':
                        me = sm.oauth_remotes[provider].get('user')
                        return {'username': me.data.get('login')}
                    else:
                        return {}
        """

        def wraps(provider, response=None):
            ret = f(self, provider, response=response)
            # Checks if decorator is well behaved and returns a dict as supposed.
            if not type(ret) == dict:
                log.error(
                    "OAuth user info decorated function "
                    "did not returned a dict, but: {0}".format(type(ret))
                )
                return {}
            return ret

        self.oauth_user_info = wraps
        return wraps

    def get_oauth_token_key_name(self, provider):
        """
            Returns the token_key name for the oauth provider
            if none is configured defaults to oauth_token
            this is configured using OAUTH_PROVIDERS and token_key key.
        """
        for _provider in self.oauth_providers:
            if _provider["name"] == provider:
                return _provider.get("token_key", "oauth_token")

    def get_oauth_token_secret_name(self, provider):
        """
            Returns the token_secret name for the oauth provider
            if none is configured defaults to oauth_secret
            this is configured using OAUTH_PROVIDERS and token_secret
        """
        for _provider in self.oauth_providers:
            if _provider["name"] == provider:
                return _provider.get("token_secret", "oauth_token_secret")

    def set_oauth_session(self, provider, oauth_response):
        """
            Set the current session with OAuth user secrets
        """
        # Get this provider key names for token_key and token_secret
        token_key = self.appbuilder.sm.get_oauth_token_key_name(provider)
        token_secret = self.appbuilder.sm.get_oauth_token_secret_name(provider)
        # Save users token on encrypted session cookie
        session["oauth"] = (
            oauth_response[token_key],
            oauth_response.get(token_secret, ""),
        )
        session["oauth_provider"] = provider

    def get_oauth_user_info(self, provider, resp):
        """
            Since there are different OAuth API's with different ways to
            retrieve user info
        """
        # for GITHUB
        if provider == "github" or provider == "githublocal":
            me = self.appbuilder.sm.oauth_remotes[provider].get("user")
            log.debug("User info from Github: {0}".format(me.data))
            return {"username": "github_" + me.data.get("login")}
        # for twitter
        if provider == "twitter":
            me = self.appbuilder.sm.oauth_remotes[provider].get("account/settings.json")
            log.debug("User info from Twitter: {0}".format(me.data))
            return {"username": "twitter_" + me.data.get("screen_name", "")}
        # for linkedin
        if provider == "linkedin":
            me = self.appbuilder.sm.oauth_remotes[provider].get(
                "people/~:(id,email-address,first-name,last-name)?format=json"
            )
            log.debug("User info from Linkedin: {0}".format(me.data))
            return {
                "username": "linkedin_" + me.data.get("id", ""),
                "email": me.data.get("email-address", ""),
                "first_name": me.data.get("firstName", ""),
                "last_name": me.data.get("lastName", ""),
            }
        # for Google
        if provider == "google":
            me = self.appbuilder.sm.oauth_remotes[provider].get("userinfo")
            log.debug("User info from Google: {0}".format(me.data))
            return {
                "username": "google_" + me.data.get("id", ""),
                "first_name": me.data.get("given_name", ""),
                "last_name": me.data.get("family_name", ""),
                "email": me.data.get("email", ""),
            }
        # for Azure AD Tenant. Azure OAuth response contains
        # JWT token which has user info.
        # JWT token needs to be base64 decoded.
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/
        # active-directory-protocols-oauth-code
        if provider == "azure":
            log.debug("Azure response received : {0}".format(resp))
            id_token = resp["id_token"]
            log.debug(str(id_token))
            me = self._azure_jwt_token_parse(id_token)
            log.debug("Parse JWT token : {0}".format(me))
            return {
                "name": me["name"],
                "email": me["upn"],
                "first_name": me["given_name"],
                "last_name": me["family_name"],
                "id": me["oid"],
                "username": me["oid"],
            }
        else:
            return {}

    def _azure_parse_jwt(self, id_token):
        jwt_token_parts = r"^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$"
        matches = re.search(jwt_token_parts, id_token)
        if not matches or len(matches.groups()) < 3:
            log.error("Unable to parse token.")
            return {}
        return {
            "header": matches.group(1),
            "Payload": matches.group(2),
            "Sig": matches.group(3),
        }

    def _azure_jwt_token_parse(self, id_token):
        jwt_split_token = self._azure_parse_jwt(id_token)
        if not jwt_split_token:
            return

        jwt_payload = jwt_split_token["Payload"]
        # Prepare for base64 decoding
        payload_b64_string = jwt_payload
        payload_b64_string += "=" * (4 - ((len(jwt_payload) % 4)))
        decoded_payload = base64.urlsafe_b64decode(payload_b64_string.encode("ascii"))

        if not decoded_payload:
            log.error("Payload of id_token could not be base64 url decoded.")
            return

        jwt_decoded_payload = json.loads(decoded_payload.decode("utf-8"))

        return jwt_decoded_payload

    def register_views(self):
        if not self.appbuilder.app.config.get("FAB_ADD_SECURITY_VIEWS", True):
            return
        # Security APIs
        self.appbuilder.add_api(self.security_api)

        if self.auth_user_registration:
            if self.auth_type == AUTH_DB:
                self.registeruser_view = self.registeruserdbview()
            elif self.auth_type == AUTH_OID:
                self.registeruser_view = self.registeruseroidview()
            elif self.auth_type == AUTH_OAUTH:
                self.registeruser_view = self.registeruseroauthview()
            if self.registeruser_view:
                self.appbuilder.add_view_no_menu(self.registeruser_view)

        self.appbuilder.add_view_no_menu(self.resetpasswordview())
        self.appbuilder.add_view_no_menu(self.resetmypasswordview())
        self.appbuilder.add_view_no_menu(self.userinfoeditview())

        if self.auth_type == AUTH_DB:
            self.user_view = self.userdbmodelview
            self.auth_view = self.authdbview()

        elif self.auth_type == AUTH_LDAP:
            self.user_view = self.userldapmodelview
            self.auth_view = self.authldapview()
        elif self.auth_type == AUTH_OAUTH:
            self.user_view = self.useroauthmodelview
            self.auth_view = self.authoauthview()
        elif self.auth_type == AUTH_REMOTE_USER:
            self.user_view = self.userremoteusermodelview
            self.auth_view = self.authremoteuserview()
        else:
            self.user_view = self.useroidmodelview
            self.auth_view = self.authoidview()
            if self.auth_user_registration:
                pass
                # self.registeruser_view = self.registeruseroidview()
                # self.appbuilder.add_view_no_menu(self.registeruser_view)

        self.appbuilder.add_view_no_menu(self.auth_view)

        self.user_view = self.appbuilder.add_view(
            self.user_view,
            "List Users",
            icon="fa-user",
            label=_("List Users"),
            category="Security",
            category_icon="fa-cogs",
            category_label=_("Security"),
        )

        role_view = self.appbuilder.add_view(
            self.rolemodelview,
            "List Roles",
            icon="fa-group",
            label=_("List Roles"),
            category="Security",
            category_icon="fa-cogs",
        )
        role_view.related_views = [self.user_view.__class__]

        if self.userstatschartview:
            self.appbuilder.add_view(
                self.userstatschartview,
                "User's Statistics",
                icon="fa-bar-chart-o",
                label=_("User's Statistics"),
                category="Security",
            )
        if self.auth_user_registration:
            self.appbuilder.add_view(
                self.registerusermodelview,
                "User's Statistics",
                icon="fa-user-plus",
                label=_("User Registrations"),
                category="Security",
            )
        self.appbuilder.menu.add_separator("Security")
        if self.appbuilder.app.config.get("FAB_ADD_SECURITY_PERMISSION_VIEW", True):
            self.appbuilder.add_view(
                self.permissionmodelview,
                "Base Permissions",
                icon="fa-lock",
                label=_("Base Permissions"),
                category="Security",
            )
        if self.appbuilder.app.config.get("FAB_ADD_SECURITY_VIEW_MENU_VIEW", True):
            self.appbuilder.add_view(
                self.viewmenumodelview,
                "Views/Menus",
                icon="fa-list-alt",
                label=_("Views/Menus"),
                category="Security",
            )
        if self.appbuilder.app.config.get(
            "FAB_ADD_SECURITY_PERMISSION_VIEWS_VIEW", True
        ):
            self.appbuilder.add_view(
                self.permissionviewmodelview,
                "Permission on Views/Menus",
                icon="fa-link",
                label=_("Permission on Views/Menus"),
                category="Security",
            )

    def create_db(self):
        """
            Setups the DB, creates admin and public roles if they don't exist.
        """
        roles_mapping = self.appbuilder.get_app.config.get("FAB_ROLES_MAPPING", {})
        for pk, name in roles_mapping.items():
            self.update_role(pk, name)
        for role_name in self.builtin_roles:
            self.add_role(role_name)
        if self.auth_role_admin not in self.builtin_roles:
            self.add_role(self.auth_role_admin)
        self.add_role(self.auth_role_public)
        if self.count_users() == 0:
            log.warning(LOGMSG_WAR_SEC_NO_USER)

    def reset_password(self, userid, password):
        """
            Change/Reset a user's password for authdb.
            Password will be hashed and saved.

            :param userid:
                the user.id to reset the password
            :param password:
                The clear text password to reset and save hashed on the db
        """
        user = self.get_user_by_id(userid)
        user.password = generate_password_hash(password)
        self.update_user(user)

    def update_user_auth_stat(self, user, success=True):
        """
            Update authentication successful to user.

            :param user:
                The authenticated user model
            :param success:
                Default to true, if false increments fail_login_count on user model
        """
        if not user.login_count:
            user.login_count = 0
        if not user.fail_login_count:
            user.fail_login_count = 0
        if success:
            user.login_count += 1
            user.fail_login_count = 0
        else:
            user.fail_login_count += 1
        user.last_login = datetime.datetime.now()
        self.update_user(user)

    def auth_user_db(self, username, password):
        """
            Method for authenticating user, auth db style

            :param username:
                The username or registered email address
            :param password:
                The password, will be tested against hashed password on db
        """
        if username is None or username == "":
            return None
        user = self.find_user(username=username)
        if user is None:
            user = self.find_user(email=username)
        if user is None or (not user.is_active):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
            return None
        elif check_password_hash(user.password, password):
            self.update_user_auth_stat(user, True)
            return user
        else:
            self.update_user_auth_stat(user, False)
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
            return None

    def _search_ldap(self, ldap, con, username):
        """
            Searches LDAP for user, assumes ldap_search is set.

            :param ldap: The ldap module reference
            :param con: The ldap connection
            :param username: username to match with auth_ldap_uid_field
            :return: ldap object array
        """
        if self.auth_ldap_append_domain:
            username = username + "@" + self.auth_ldap_append_domain
        if self.auth_ldap_search_filter:
            filter_str = "(&%s(%s=%s))" % (
                self.auth_ldap_search_filter,
                self.auth_ldap_uid_field,
                username,
            )
        else:
            filter_str = "(%s=%s)" % (self.auth_ldap_uid_field, username)
        user = con.search_s(
            self.auth_ldap_search,
            ldap.SCOPE_SUBTREE,
            filter_str,
            [
                self.auth_ldap_firstname_field,
                self.auth_ldap_lastname_field,
                self.auth_ldap_email_field,
            ],
        )
        if user:
            if not user[0][0]:
                return None
        return user

    def _bind_indirect_user(self, ldap, con):
        """
            If using AUTH_LDAP_BIND_USER bind this user before performing search
            :param ldap: The ldap module reference
            :param con: The ldap connection
        """
        indirect_user = self.auth_ldap_bind_user
        if indirect_user:
            indirect_password = self.auth_ldap_bind_password
            log.debug("LDAP indirect bind with: {0}".format(indirect_user))
            con.bind_s(indirect_user, indirect_password)
            log.debug("LDAP BIND indirect OK")

    def _bind_ldap(self, ldap, con, username, password):
        """
            Private to bind/Authenticate a user.
            If AUTH_LDAP_BIND_USER exists then it will bind first with it,
            next will search the LDAP server using the username with UID
            and try to bind to it (OpenLDAP).
            If AUTH_LDAP_BIND_USER does not exit, will bind with username/password
        """
        try:
            if self.auth_ldap_bind_user:
                self._bind_indirect_user(ldap, con)
                user = self._search_ldap(ldap, con, username)
                if user:
                    log.debug("LDAP got User {0}".format(user))
                    # username = DN from search
                    username = user[0][0]
                else:
                    log.debug("LDAP bind failure: user not found")
                    return False
            log.debug("LDAP bind with: {0} {1}".format(username, "XXXXXX"))
            if self.auth_ldap_username_format:
                username = self.auth_ldap_username_format % username
            if self.auth_ldap_append_domain:
                username = username + "@" + self.auth_ldap_append_domain
            con.bind_s(username, password)
            log.debug("LDAP bind OK: {0}".format(username))
            return True
        except ldap.INVALID_CREDENTIALS:
            log.debug("LDAP bind failure: invalid credentials")
            return False

    @staticmethod
    def ldap_extract(ldap_dict, field, fallback):
        if not ldap_dict.get(field):
            return fallback
        return ldap_dict[field][0].decode("utf-8") or fallback

    def auth_user_ldap(self, username, password):
        """
            Method for authenticating user, auth LDAP style.
            depends on ldap module that is not mandatory requirement
            for F.A.B.

            :param username:
                The username
            :param password:
                The password
        """
        if username is None or username == "":
            return None
        user = self.find_user(username=username)
        if user is not None and (not user.is_active):
            return None
        else:
            try:
                import ldap
            except Exception:
                raise Exception("No ldap library for python.")
            try:
                if self.auth_ldap_allow_self_signed:
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
                    ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
                elif self.auth_ldap_tls_demand:
                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
                    ldap.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
                if self.auth_ldap_tls_cacertdir:
                    ldap.set_option(
                        ldap.OPT_X_TLS_CACERTDIR, self.auth_ldap_tls_cacertdir
                    )
                if self.auth_ldap_tls_cacertfile:
                    ldap.set_option(
                        ldap.OPT_X_TLS_CACERTFILE, self.auth_ldap_tls_cacertfile
                    )
                if self.auth_ldap_tls_certfile and self.auth_ldap_tls_keyfile:
                    ldap.set_option(
                        ldap.OPT_X_TLS_CERTFILE, self.auth_ldap_tls_certfile
                    )
                    ldap.set_option(ldap.OPT_X_TLS_KEYFILE, self.auth_ldap_tls_keyfile)
                con = ldap.initialize(self.auth_ldap_server)
                con.set_option(ldap.OPT_REFERRALS, 0)
                if self.auth_ldap_use_tls:
                    try:
                        con.start_tls_s()
                    except Exception:
                        log.info(
                            LOGMSG_ERR_SEC_AUTH_LDAP_TLS.format(self.auth_ldap_server)
                        )
                        return None
                # Authenticate user
                if not self._bind_ldap(ldap, con, username, password):
                    if user:
                        self.update_user_auth_stat(user, False)
                    log.warning(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
                    return None
                # If user does not exist on the DB and not self user registration, go away
                if not user and not self.auth_user_registration:
                    return None
                # User does not exist, create one if self registration.
                elif not user and self.auth_user_registration:
                    self._bind_indirect_user(ldap, con)
                    new_user = self._search_ldap(ldap, con, username)
                    if not new_user:
                        log.warning(LOGMSG_WAR_SEC_NOLDAP_OBJ.format(username))
                        return None
                    ldap_user_info = new_user[0][1]
                    if self.auth_user_registration and user is None:
                        user = self.add_user(
                            username=username,
                            first_name=self.ldap_extract(
                                ldap_user_info, self.auth_ldap_firstname_field, username
                            ),
                            last_name=self.ldap_extract(
                                ldap_user_info, self.auth_ldap_lastname_field, username
                            ),
                            email=self.ldap_extract(
                                ldap_user_info,
                                self.auth_ldap_email_field,
                                username + "@email.notfound",
                            ),
                            role=self.find_role(self.auth_user_registration_role),
                        )

                self.update_user_auth_stat(user)
                return user

            except ldap.LDAPError as e:
                msg = None
                if isinstance(e, dict):
                    msg = getattr(e, "message", None)
                if msg is not None and "desc" in msg:
                    log.error(LOGMSG_ERR_SEC_AUTH_LDAP.format(e.message["desc"]))
                    return None
                else:
                    log.error(e)
                    return None

    def auth_user_oid(self, email):
        """
            OpenID user Authentication

            :param email: user's email to authenticate
            :type self: User model
        """
        user = self.find_user(email=email)
        if user is None or (not user.is_active):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(email))
            return None
        else:
            self.update_user_auth_stat(user)
            return user

    def auth_user_remote_user(self, username):
        """
            REMOTE_USER user Authentication

            :param username: user's username for remote auth
            :type self: User model
        """
        user = self.find_user(username=username)

        # User does not exist, create one if auto user registration.
        if user is None and self.auth_user_registration:
            user = self.add_user(
                # All we have is REMOTE_USER, so we set
                # the other fields to blank.
                username=username,
                first_name=username,
                last_name="-",
                email=username + "@email.notfound",
                role=self.find_role(self.auth_user_registration_role),
            )

        # If user does not exist on the DB and not auto user registration,
        # or user is inactive, go away.
        elif user is None or (not user.is_active):
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(username))
            return None

        self.update_user_auth_stat(user)
        return user

    def auth_user_oauth(self, userinfo):
        """
            OAuth user Authentication

            :userinfo: dict with user information the keys have the same name
            as User model columns.
        """
        if "username" in userinfo:
            user = self.find_user(username=userinfo["username"])
        elif "email" in userinfo:
            user = self.find_user(email=userinfo["email"])
        else:
            log.error("User info does not have username or email {0}".format(userinfo))
            return None
        # User is disabled
        if user and not user.is_active:
            log.info(LOGMSG_WAR_SEC_LOGIN_FAILED.format(userinfo))
            return None
        # If user does not exist on the DB and not self user registration, go away
        if not user and not self.auth_user_registration:
            return None
        # User does not exist, create one if self registration.
        if not user:
            user = self.add_user(
                username=userinfo["username"],
                first_name=userinfo.get("first_name", ""),
                last_name=userinfo.get("last_name", ""),
                email=userinfo.get("email", ""),
                role=self.find_role(self.auth_user_registration_role),
            )
            if not user:
                log.error("Error creating a new OAuth user %s" % userinfo["username"])
                return None
        self.update_user_auth_stat(user)
        return user

    """
        ----------------------------------------
            PERMISSION ACCESS CHECK
        ----------------------------------------
    """

    def is_item_public(self, permission_name, view_name):
        """
            Check if view has public permissions

            :param permission_name:
                the permission: can_show, can_edit...
            :param view_name:
                the name of the class view (child of BaseView)
        """
        permissions = self.get_public_permissions()
        if permissions:
            for i in permissions:
                if (view_name == i.view_menu.name) and (
                    permission_name == i.permission.name
                ):
                    return True
            return False
        else:
            return False

    def _has_access_builtin_roles(
        self, role, permission_name: str, view_name: str
    ) -> bool:
        """
            Checks permission on builtin role
        """
        builtin_pvms = self.builtin_roles.get(role.name, [])
        for pvm in builtin_pvms:
            _view_name = pvm[0]
            _permission_name = pvm[1]
            if re.match(_view_name, view_name) and re.match(
                _permission_name, permission_name
            ):
                return True
        return False

    def _has_view_access(
        self, user: object, permission_name: str, view_name: str
    ) -> bool:
        roles = user.roles
        db_role_ids = list()
        # First check against builtin (statically configured) roles
        # because no database query is needed
        for role in roles:
            if role.name in self.builtin_roles:
                if self._has_access_builtin_roles(role, permission_name, view_name):
                    return True
            else:
                db_role_ids.append(role.id)

        # Then check against database-stored roles
        return self.exist_permission_on_roles(view_name, permission_name, db_role_ids)

    def _get_user_permission_view_menus(
        self, user: object, permission_name: str, view_menus_name: List[str]
    ) -> Set[str]:
        """
        Return a set of view menu names with a certain permission name
        that a user has access to. Mainly used to fetch all menu permissions
        on a single db call, will also check public permissions and builtin roles
        """
        db_role_ids = list()
        if user is None:
            # include public role
            roles = [self.get_public_role()]
        else:
            roles = user.roles
        # First check against builtin (statically configured) roles
        # because no database query is needed
        result = set()
        for role in roles:
            if role.name in self.builtin_roles:
                for view_menu_name in view_menus_name:
                    if self._has_access_builtin_roles(
                        role, permission_name, view_menu_name
                    ):
                        result.add(view_menu_name)
            else:
                db_role_ids.append(role.id)
        # Then check against database-stored roles
        pvms_names = [
            pvm.view_menu.name
            for pvm in self.find_roles_permission_view_menus(
                permission_name, db_role_ids
            )
        ]
        result.update(pvms_names)
        return result

    def has_access(self, permission_name, view_name):
        """
            Check if current user or public has access to view or menu
        """
        if current_user.is_authenticated:
            return self._has_view_access(g.user, permission_name, view_name)
        elif current_user_jwt:
            return self._has_view_access(current_user_jwt, permission_name, view_name)
        else:
            return self.is_item_public(permission_name, view_name)

    def get_user_menu_access(self, menu_names: List[str] = None) -> Set[str]:
        if current_user.is_authenticated:
            return self._get_user_permission_view_menus(
                g.user, "menu_access", view_menus_name=menu_names
            )
        elif current_user_jwt:
            return self._get_user_permission_view_menus(
                current_user_jwt, "menu_access", view_menus_name=menu_names
            )
        else:
            return self._get_user_permission_view_menus(
                None, "menu_access", view_menus_name=menu_names
            )

    def add_permissions_view(self, base_permissions, view_menu):
        """
            Adds a permission on a view menu to the backend

            :param base_permissions:
                list of permissions from view (all exposed methods):
                 'can_add','can_edit' etc...
            :param view_menu:
                name of the view or menu to add
        """
        view_menu_db = self.add_view_menu(view_menu)
        perm_views = self.find_permissions_view_menu(view_menu_db)

        if not perm_views:
            # No permissions yet on this view
            for permission in base_permissions:
                pv = self.add_permission_view_menu(permission, view_menu)
                if self.auth_role_admin not in self.builtin_roles:
                    role_admin = self.find_role(self.auth_role_admin)
                    self.add_permission_role(role_admin, pv)
        else:
            # Permissions on this view exist but....
            role_admin = self.find_role(self.auth_role_admin)
            for permission in base_permissions:
                # Check if base view permissions exist
                if not self.exist_permission_on_views(perm_views, permission):
                    pv = self.add_permission_view_menu(permission, view_menu)
                    if self.auth_role_admin not in self.builtin_roles:
                        self.add_permission_role(role_admin, pv)
            for perm_view in perm_views:
                if perm_view.permission is None:
                    # Skip this perm_view, it has a null permission
                    continue
                if perm_view.permission.name not in base_permissions:
                    # perm to delete
                    roles = self.get_all_roles()
                    perm = self.find_permission(perm_view.permission.name)
                    # del permission from all roles
                    for role in roles:
                        self.del_permission_role(role, perm)
                    self.del_permission_view_menu(perm_view.permission.name, view_menu)
                elif (
                    self.auth_role_admin not in self.builtin_roles
                    and perm_view not in role_admin.permissions
                ):
                    # Role Admin must have all permissions
                    self.add_permission_role(role_admin, perm_view)

    def add_permissions_menu(self, view_menu_name):
        """
            Adds menu_access to menu on permission_view_menu

            :param view_menu_name:
                The menu name
        """
        self.add_view_menu(view_menu_name)
        pv = self.find_permission_view_menu("menu_access", view_menu_name)
        if not pv:
            pv = self.add_permission_view_menu("menu_access", view_menu_name)
        if self.auth_role_admin not in self.builtin_roles:
            role_admin = self.find_role(self.auth_role_admin)
            self.add_permission_role(role_admin, pv)

    def security_cleanup(self, baseviews, menus):
        """
            Will cleanup all unused permissions from the database

            :param baseviews: A list of BaseViews class
            :param menus: Menu class
        """
        viewsmenus = self.get_all_view_menu()
        roles = self.get_all_roles()
        for viewmenu in viewsmenus:
            found = False
            for baseview in baseviews:
                if viewmenu.name == baseview.class_permission_name:
                    found = True
                    break
            if menus.find(viewmenu.name):
                found = True
            if not found:
                permissions = self.find_permissions_view_menu(viewmenu)
                for permission in permissions:
                    for role in roles:
                        self.del_permission_role(role, permission)
                    self.del_permission_view_menu(
                        permission.permission.name, viewmenu.name
                    )
                self.del_view_menu(viewmenu.name)
        self.security_converge(baseviews, menus)

    @staticmethod
    def _get_new_old_permissions(baseview) -> Dict:
        ret = dict()
        for method_name, permission_name in baseview.method_permission_name.items():
            old_permission_name = baseview.previous_method_permission_name.get(
                method_name
            )
            # Actions do not get prefix when normally defined
            if hasattr(baseview, "actions") and baseview.actions.get(
                old_permission_name
            ):
                permission_prefix = ""
            else:
                permission_prefix = PERMISSION_PREFIX
            if old_permission_name:
                if PERMISSION_PREFIX + permission_name not in ret:
                    ret[PERMISSION_PREFIX + permission_name] = {
                        permission_prefix + old_permission_name
                    }
                else:
                    ret[PERMISSION_PREFIX + permission_name].add(
                        permission_prefix + old_permission_name
                    )
        return ret

    @staticmethod
    def _add_state_transition(
        state_transition: Dict,
        old_view_name: str,
        old_perm_name: str,
        view_name: str,
        perm_name: str,
    ) -> None:
        old_pvm = state_transition["add"].get((old_view_name, old_perm_name))
        if old_pvm:
            state_transition["add"][(old_view_name, old_perm_name)].add(
                (view_name, perm_name)
            )
        else:
            state_transition["add"][(old_view_name, old_perm_name)] = {
                (view_name, perm_name)
            }
        state_transition["del_role_pvm"].add((old_view_name, old_perm_name))
        state_transition["del_views"].add(old_view_name)
        state_transition["del_perms"].add(old_perm_name)

    @staticmethod
    def _update_del_transitions(state_transitions: Dict, baseviews: List) -> None:
        """
            Mutates state_transitions, loop baseviews and prunes all
            views and permissions that are not to delete because references
            exist.

        :param baseview:
        :param state_transitions:
        :return:
        """
        for baseview in baseviews:
            state_transitions["del_views"].discard(baseview.class_permission_name)
            for permission in baseview.base_permissions:
                state_transitions["del_role_pvm"].discard(
                    (baseview.class_permission_name, permission)
                )
                state_transitions["del_perms"].discard(permission)

    def create_state_transitions(self, baseviews: List, menus: List) -> Dict:
        """
            Creates a Dict with all the necessary vm/permission transitions

            Dict: {
                    "add": {(<VM>, <PERM>): ((<VM>, PERM), ... )}
                    "del_role_pvm": ((<VM>, <PERM>), ...)
                    "del_views": (<VM>, ... )
                    "del_perms": (<PERM>, ... )
                  }

        :param baseviews: List with all the registered BaseView, BaseApi
        :param menus: List with all the menu entries
        :return: Dict with state transitions
        """
        state_transitions = {
            "add": {},
            "del_role_pvm": set(),
            "del_views": set(),
            "del_perms": set(),
        }
        for baseview in baseviews:
            add_all_flag = False
            new_view_name = baseview.class_permission_name
            permission_mapping = self._get_new_old_permissions(baseview)
            if baseview.previous_class_permission_name:
                old_view_name = baseview.previous_class_permission_name
                add_all_flag = True
            else:
                new_view_name = baseview.class_permission_name
                old_view_name = new_view_name
            for new_perm_name in baseview.base_permissions:
                if add_all_flag:
                    old_perm_names = permission_mapping.get(new_perm_name)
                    old_perm_names = old_perm_names or (new_perm_name,)
                    for old_perm_name in old_perm_names:
                        self._add_state_transition(
                            state_transitions,
                            old_view_name,
                            old_perm_name,
                            new_view_name,
                            new_perm_name,
                        )
                else:
                    old_perm_names = permission_mapping.get(new_perm_name) or set()
                    for old_perm_name in old_perm_names:
                        self._add_state_transition(
                            state_transitions,
                            old_view_name,
                            old_perm_name,
                            new_view_name,
                            new_perm_name,
                        )
        self._update_del_transitions(state_transitions, baseviews)
        return state_transitions

    def security_converge(self, baseviews: List, menus: List, dry=False) -> Dict:
        """
            Converges overridden permissions on all registered views/api
            will compute all necessary operations from `class_permissions_name`,
            `previous_class_permission_name`, method_permission_name`,
            `previous_method_permission_name` class attributes.

        :param baseviews: List of registered views/apis
        :param menus: List of menu items
        :param dry: If True will not change DB
        :return: Dict with the necessary operations (state_transitions)
        """
        state_transitions = self.create_state_transitions(baseviews, menus)
        if dry:
            return state_transitions
        if not state_transitions:
            log.info("No state transitions found")
            return dict()
        log.debug(f"State transitions: {state_transitions}")
        roles = self.get_all_roles()
        for role in roles:
            permissions = list(role.permissions)
            for pvm in permissions:
                new_pvm_states = state_transitions["add"].get(
                    (pvm.view_menu.name, pvm.permission.name)
                )
                if not new_pvm_states:
                    continue
                for new_pvm_state in new_pvm_states:
                    new_pvm = self.add_permission_view_menu(
                        new_pvm_state[1], new_pvm_state[0]
                    )
                    self.add_permission_role(role, new_pvm)
                if (pvm.view_menu.name, pvm.permission.name) in state_transitions[
                    "del_role_pvm"
                ]:
                    self.del_permission_role(role, pvm)
        for pvm in state_transitions["del_role_pvm"]:
            self.del_permission_view_menu(pvm[1], pvm[0], cascade=False)
        for view_name in state_transitions["del_views"]:
            self.del_view_menu(view_name)
        for permission_name in state_transitions["del_perms"]:
            self.del_permission(permission_name)
        return state_transitions

    """
     ---------------------------
     INTERFACE ABSTRACT METHODS
     ---------------------------

     ---------------------
     PRIMITIVES FOR USERS
    ----------------------
    """

    def find_register_user(self, registration_hash):
        """
            Generic function to return user registration
        """
        raise NotImplementedError

    def add_register_user(
        self, username, first_name, last_name, email, password="", hashed_password=""
    ):
        """
            Generic function to add user registration
        """
        raise NotImplementedError

    def del_register_user(self, register_user):
        """
            Generic function to delete user registration
        """
        raise NotImplementedError

    def get_user_by_id(self, pk):
        """
            Generic function to return user by it's id (pk)
        """
        raise NotImplementedError

    def find_user(self, username=None, email=None):
        """
            Generic function find a user by it's username or email
        """
        raise NotImplementedError

    def get_all_users(self):
        """
            Generic function that returns all exsiting users
        """
        raise NotImplementedError

    def add_user(self, username, first_name, last_name, email, role, password=""):
        """
            Generic function to create user
        """
        raise NotImplementedError

    def update_user(self, user):
        """
            Generic function to update user

            :param user: User model to update to database
        """
        raise NotImplementedError

    def count_users(self):
        """
            Generic function to count the existing users
        """
        raise NotImplementedError

    """
    ----------------------
     PRIMITIVES FOR ROLES
    ----------------------
    """

    def find_role(self, name):
        raise NotImplementedError

    def add_role(self, name):
        raise NotImplementedError

    def update_role(self, pk, name):
        raise NotImplementedError

    def get_all_roles(self):
        raise NotImplementedError

    """
    ----------------------------
     PRIMITIVES FOR PERMISSIONS
    ----------------------------
    """

    def get_public_role(self):
        """
            returns all permissions from public role
        """
        raise NotImplementedError

    def get_public_permissions(self):
        """
            returns all permissions from public role
        """
        raise NotImplementedError

    def find_permission(self, name):
        """
            Finds and returns a Permission by name
        """
        raise NotImplementedError

    def find_roles_permission_view_menus(
        self, permission_name: str, role_ids: List[int]
    ):
        raise NotImplementedError

    def exist_permission_on_roles(
        self, view_name: str, permission_name: str, role_ids: List[int]
    ) -> bool:
        """
            Finds and returns permission views for a group of roles
        """
        raise NotImplementedError

    def add_permission(self, name):
        """
            Adds a permission to the backend, model permission

            :param name:
                name of the permission: 'can_add','can_edit' etc...
        """
        raise NotImplementedError

    def del_permission(self, name):
        """
            Deletes a permission from the backend, model permission

            :param name:
                name of the permission: 'can_add','can_edit' etc...
        """
        raise NotImplementedError

    """
    ----------------------
     PRIMITIVES VIEW MENU
    ----------------------
    """

    def find_view_menu(self, name):
        """
            Finds and returns a ViewMenu by name
        """
        raise NotImplementedError

    def get_all_view_menu(self):
        raise NotImplementedError

    def add_view_menu(self, name):
        """
            Adds a view or menu to the backend, model view_menu
            param name:
                name of the view menu to add
        """
        raise NotImplementedError

    def del_view_menu(self, name):
        """
            Deletes a ViewMenu from the backend

            :param name:
                name of the ViewMenu
        """
        raise NotImplementedError

    """
    ----------------------
     PERMISSION VIEW MENU
    ----------------------
    """

    def find_permission_view_menu(self, permission_name, view_menu_name):
        """
            Finds and returns a PermissionView by names
        """
        raise NotImplementedError

    def find_permissions_view_menu(self, view_menu):
        """
            Finds all permissions from ViewMenu, returns list of PermissionView

            :param view_menu: ViewMenu object
            :return: list of PermissionView objects
        """
        raise NotImplementedError

    def add_permission_view_menu(self, permission_name, view_menu_name):
        """
            Adds a permission on a view or menu to the backend

            :param permission_name:
                name of the permission to add: 'can_add','can_edit' etc...
            :param view_menu_name:
                name of the view menu to add
        """
        raise NotImplementedError

    def del_permission_view_menu(self, permission_name, view_menu_name, cascade=True):
        raise NotImplementedError

    def exist_permission_on_views(self, lst, item):
        raise NotImplementedError

    def exist_permission_on_view(self, lst, permission, view_menu):
        raise NotImplementedError

    def add_permission_role(self, role, perm_view):
        """
            Add permission-ViewMenu object to Role

            :param role:
                The role object
            :param perm_view:
                The PermissionViewMenu object
        """
        raise NotImplementedError

    def del_permission_role(self, role, perm_view):
        """
            Remove permission-ViewMenu object to Role

            :param role:
                The role object
            :param perm_view:
                The PermissionViewMenu object
        """
        raise NotImplementedError

    def load_user(self, pk):
        return self.get_user_by_id(int(pk))

    def load_user_jwt(self, pk):
        user = self.load_user(pk)
        # Set flask g.user to JWT user, we can't do it on before request
        g.user = user
        return user

    @staticmethod
    def before_request():
        g.user = current_user
superset@11d608080892:/usr/local/lib/python3.6/site-packages/flask_appbuilder/security$ ls
__init__.py  __pycache__  api.py  decorators.py  forms.py  manager.py  mongoengine  registerviews.py  sqla  views.py
superset@11d608080892:/usr/local/lib/python3.6/site-packages/flask_appbuilder/security$ cd ../
superset@11d608080892:/usr/local/lib/python3.6/site-packages/flask_appbuilder$ ks
bash: ks: command not found
superset@11d608080892:/usr/local/lib/python3.6/site-packages/flask_appbuilder$ ls
__init__.py  actions.py  base.py         charts      const.py       fieldwidgets.py  forms.py     models    templates    upload.py                         views.py
__pycache__  api         basemanager.py  cli.py      exceptions.py  filemanager.py   menu.py      security  tests        urltools.py                       widgets.py
_compat.py   babel       baseviews.py    console.py  fields.py      filters.py       messages.py  static    translations  validators.py
superset@11d608080892:/usr/local/lib/python3.6/site-packages/flask_appbuilder$ cat core.py
cat: core.py: No such file or directory
superset@11d608080892:/usr/local/lib/python3.6/site-packages/flask_appbuilder$ cd ../
superset@11d608080892:/usr/local/lib/python3.6/site-packages$ cd wtforms/fields/
superset@11d608080892:/usr/local/lib/python3.6/site-packages/wtforms/fields$ ls
__init__.py  __pycache__  core.py  html5.py  simple.py
superset@11d608080892:/usr/local/lib/python3.6/site-packages/wtforms/fields$ cat core.py
from __future__ import unicode_literals

import datetime
import decimal
import itertools

from copy import copy

from wtforms import widgets
from wtforms.compat import text_type, izip
from wtforms.i18n import DummyTranslations
from wtforms.validators import StopValidation
from wtforms.utils import unset_value


__all__ = (
    'BooleanField', 'DecimalField', 'DateField', 'DateTimeField', 'FieldList',
    'FloatField', 'FormField', 'IntegerField', 'RadioField', 'SelectField',
    'SelectMultipleField', 'StringField', 'TimeField',
)


class Field(object):
    """
    Field base class
    """
    errors = tuple()
    process_errors = tuple()
    raw_data = None
    validators = tuple()
    widget = None
    _formfield = True
    _translations = DummyTranslations()
    do_not_call_in_templates = True  # Allow Django 1.4 traversal

    def __new__(cls, *args, **kwargs):
        if '_form' in kwargs and '_name' in kwargs:
            return super(Field, cls).__new__(cls)
        else:
            return UnboundField(cls, *args, **kwargs)

    def __init__(self, label=None, validators=None, filters=tuple(),
                 description='', id=None, default=None, widget=None,
                 render_kw=None, _form=None, _name=None, _prefix='',
                 _translations=None, _meta=None):
        """
        Construct a new field.

        :param label:
            The label of the field.
        :param validators:
            A sequence of validators to call when `validate` is called.
        :param filters:
            A sequence of filters which are run on input data by `process`.
        :param description:
            A description for the field, typically used for help text.
        :param id:
            An id to use for the field. A reasonable default is set by the form,
            and you shouldn't need to set this manually.
        :param default:
            The default value to assign to the field, if no form or object
            input is provided. May be a callable.
        :param widget:
            If provided, overrides the widget used to render the field.
        :param dict render_kw:
            If provided, a dictionary which provides default keywords that
            will be given to the widget at render time.
        :param _form:
            The form holding this field. It is passed by the form itself during
            construction. You should never pass this value yourself.
        :param _name:
            The name of this field, passed by the enclosing form during its
            construction. You should never pass this value yourself.
        :param _prefix:
            The prefix to prepend to the form name of this field, passed by
            the enclosing form during construction.
        :param _translations:
            A translations object providing message translations. Usually
            passed by the enclosing form during construction. See
            :doc:`I18n docs <i18n>` for information on message translations.
        :param _meta:
            If provided, this is the 'meta' instance from the form. You usually
            don't pass this yourself.

        If `_form` and `_name` isn't provided, an :class:`UnboundField` will be
        returned instead. Call its :func:`bind` method with a form instance and
        a name to construct the field.
        """
        if _translations is not None:
            self._translations = _translations

        if _meta is not None:
            self.meta = _meta
        elif _form is not None:
            self.meta = _form.meta
        else:
            raise TypeError("Must provide one of _form or _meta")

        self.default = default
        self.description = description
        self.render_kw = render_kw
        self.filters = filters
        self.flags = Flags()
        self.name = _prefix + _name
        self.short_name = _name
        self.type = type(self).__name__
        self.validators = validators or list(self.validators)

        self.id = id or self.name
        self.label = Label(self.id, label if label is not None else self.gettext(_name.replace('_', ' ').title()))

        if widget is not None:
            self.widget = widget

        for v in itertools.chain(self.validators, [self.widget]):
            flags = getattr(v, 'field_flags', ())
            for f in flags:
                setattr(self.flags, f, True)

    def __unicode__(self):
        """
        Returns a HTML representation of the field. For more powerful rendering,
        see the `__call__` method.
        """
        return self()

    def __str__(self):
        """
        Returns a HTML representation of the field. For more powerful rendering,
        see the `__call__` method.
        """
        return self()

    def __html__(self):
        """
        Returns a HTML representation of the field. For more powerful rendering,
        see the :meth:`__call__` method.
        """
        return self()

    def __call__(self, **kwargs):
        """
        Render this field as HTML, using keyword args as additional attributes.

        This delegates rendering to
        :meth:`meta.render_field <wtforms.meta.DefaultMeta.render_field>`
        whose default behavior is to call the field's widget, passing any
        keyword arguments from this call along to the widget.

        In all of the WTForms HTML widgets, keyword arguments are turned to
        HTML attributes, though in theory a widget is free to do anything it
        wants with the supplied keyword arguments, and widgets don't have to
        even do anything related to HTML.
        """
        return self.meta.render_field(self, kwargs)

    def gettext(self, string):
        """
        Get a translation for the given message.

        This proxies for the internal translations object.

        :param string: A unicode string to be translated.
        :return: A unicode string which is the translated output.
        """
        return self._translations.gettext(string)

    def ngettext(self, singular, plural, n):
        """
        Get a translation for a message which can be pluralized.

        :param str singular: The singular form of the message.
        :param str plural: The plural form of the message.
        :param int n: The number of elements this message is referring to
        """
        return self._translations.ngettext(singular, plural, n)

    def validate(self, form, extra_validators=tuple()):
        """
        Validates the field and returns True or False. `self.errors` will
        contain any errors raised during validation. This is usually only
        called by `Form.validate`.

        Subfields shouldn't override this, but rather override either
        `pre_validate`, `post_validate` or both, depending on needs.

        :param form: The form the field belongs to.
        :param extra_validators: A sequence of extra validators to run.
        """
        self.errors = list(self.process_errors)
        stop_validation = False

        # Call pre_validate
        try:
            self.pre_validate(form)
        except StopValidation as e:
            if e.args and e.args[0]:
                self.errors.append(e.args[0])
            stop_validation = True
        except ValueError as e:
            self.errors.append(e.args[0])

        # Run validators
        if not stop_validation:
            chain = itertools.chain(self.validators, extra_validators)
            stop_validation = self._run_validation_chain(form, chain)

        # Call post_validate
        try:
            self.post_validate(form, stop_validation)
        except ValueError as e:
            self.errors.append(e.args[0])

        return len(self.errors) == 0

    def _run_validation_chain(self, form, validators):
        """
        Run a validation chain, stopping if any validator raises StopValidation.

        :param form: The Form instance this field belongs to.
        :param validators: a sequence or iterable of validator callables.
        :return: True if validation was stopped, False otherwise.
        """
        for validator in validators:
            try:
                validator(form, self)
            except StopValidation as e:
                if e.args and e.args[0]:
                    self.errors.append(e.args[0])
                return True
            except ValueError as e:
                self.errors.append(e.args[0])

        return False

    def pre_validate(self, form):
        """
        Override if you need field-level validation. Runs before any other
        validators.

        :param form: The form the field belongs to.
        """
        pass

    def post_validate(self, form, validation_stopped):
        """
        Override if you need to run any field-level validation tasks after
        normal validation. This shouldn't be needed in most cases.

        :param form: The form the field belongs to.
        :param validation_stopped:
            `True` if any validator raised StopValidation.
        """
        pass

    def process(self, formdata, data=unset_value):
        """
        Process incoming data, calling process_data, process_formdata as needed,
        and run filters.

        If `data` is not provided, process_data will be called on the field's
        default.

        Field subclasses usually won't override this, instead overriding the
        process_formdata and process_data methods. Only override this for
        special advanced processing, such as when a field encapsulates many
        inputs.
        """
        self.process_errors = []
        if data is unset_value:
            try:
                data = self.default()
            except TypeError:
                data = self.default

        self.object_data = data

        try:
            self.process_data(data)
        except ValueError as e:
            self.process_errors.append(e.args[0])

        if formdata is not None:
            if self.name in formdata:
                self.raw_data = formdata.getlist(self.name)
            else:
                self.raw_data = []

            try:
                self.process_formdata(self.raw_data)
            except ValueError as e:
                self.process_errors.append(e.args[0])

        try:
            for filter in self.filters:
                self.data = filter(self.data)
        except ValueError as e:
            self.process_errors.append(e.args[0])

    def process_data(self, value):
        """
        Process the Python data applied to this field and store the result.

        This will be called during form construction by the form's `kwargs` or
        `obj` argument.

        :param value: The python object containing the value to process.
        """
        self.data = value

    def process_formdata(self, valuelist):
        """
        Process data received over the wire from a form.

        This will be called during form construction with data supplied
        through the `formdata` argument.

        :param valuelist: A list of strings to process.
        """
        if valuelist:
            self.data = valuelist[0]

    def populate_obj(self, obj, name):
        """
        Populates `obj.<name>` with the field's data.

        :note: This is a destructive operation. If `obj.<name>` already exists,
               it will be overridden. Use with caution.
        """
        setattr(obj, name, self.data)


class UnboundField(object):
    _formfield = True
    creation_counter = 0

    def __init__(self, field_class, *args, **kwargs):
        UnboundField.creation_counter += 1
        self.field_class = field_class
        self.args = args
        self.kwargs = kwargs
        self.creation_counter = UnboundField.creation_counter

    def bind(self, form, name, prefix='', translations=None, **kwargs):
        kw = dict(
            self.kwargs,
            _form=form,
            _prefix=prefix,
            _name=name,
            _translations=translations,
            **kwargs
        )
        return self.field_class(*self.args, **kw)

    def __repr__(self):
        return '<UnboundField(%s, %r, %r)>' % (self.field_class.__name__, self.args, self.kwargs)


class Flags(object):
    """
    Holds a set of boolean flags as attributes.

    Accessing a non-existing attribute returns False for its value.
    """
    def __getattr__(self, name):
        if name.startswith('_'):
            return super(Flags, self).__getattr__(name)
        return False

    def __contains__(self, name):
        return getattr(self, name)

    def __repr__(self):
        flags = (name for name in dir(self) if not name.startswith('_'))
        return '<wtforms.fields.Flags: {%s}>' % ', '.join(flags)


class Label(object):
    """
    An HTML form label.
    """
    def __init__(self, field_id, text):
        self.field_id = field_id
        self.text = text

    def __str__(self):
        return self()

    def __unicode__(self):
        return self()

    def __html__(self):
        return self()

    def __call__(self, text=None, **kwargs):
        if 'for_' in kwargs:
            kwargs['for'] = kwargs.pop('for_')
        else:
            kwargs.setdefault('for', self.field_id)

        attributes = widgets.html_params(**kwargs)
        return widgets.HTMLString('<label %s>%s</label>' % (attributes, text or self.text))

    def __repr__(self):
        return 'Label(%r, %r)' % (self.field_id, self.text)


class SelectFieldBase(Field):
    option_widget = widgets.Option()

    """
    Base class for fields which can be iterated to produce options.

    This isn't a field, but an abstract base class for fields which want to
    provide this functionality.
    """
    def __init__(self, label=None, validators=None, option_widget=None, **kwargs):
        super(SelectFieldBase, self).__init__(label, validators, **kwargs)

        if option_widget is not None:
            self.option_widget = option_widget

    def iter_choices(self):
        """
        Provides data for choice widget rendering. Must return a sequence or
        iterable of (value, label, selected) tuples.
        """
        raise NotImplementedError()

    def __iter__(self):
        opts = dict(widget=self.option_widget, _name=self.name, _form=None, _meta=self.meta)
        for i, (value, label, checked) in enumerate(self.iter_choices()):
            opt = self._Option(label=label, id='%s-%d' % (self.id, i), **opts)
            opt.process(None, value)
            opt.checked = checked
            yield opt

    class _Option(Field):
        checked = False

        def _value(self):
            return text_type(self.data)


class SelectField(SelectFieldBase):
    widget = widgets.Select()

    def __init__(self, label=None, validators=None, coerce=text_type, choices=None, **kwargs):
        super(SelectField, self).__init__(label, validators, **kwargs)
        self.coerce = coerce
        self.choices = copy(choices)

    def iter_choices(self):
        for value, label in self.choices:
            yield (value, label, self.coerce(value) == self.data)

    def process_data(self, value):
        try:
            self.data = self.coerce(value)
        except (ValueError, TypeError):
            self.data = None

    def process_formdata(self, valuelist):
        if valuelist:
            try:
                self.data = self.coerce(valuelist[0])
            except ValueError:
                raise ValueError(self.gettext('Invalid Choice: could not coerce'))

    def pre_validate(self, form):
        for v, _ in self.choices:
            if self.data == v:
                break
        else:
            raise ValueError(self.gettext('Not a valid choice'))


class SelectMultipleField(SelectField):
    """
    No different from a normal select field, except this one can take (and
    validate) multiple choices.  You'll need to specify the HTML `size`
    attribute to the select field when rendering.
    """
    widget = widgets.Select(multiple=True)

    def iter_choices(self):
        for value, label in self.choices:
            selected = self.data is not None and self.coerce(value) in self.data
            yield (value, label, selected)

    def process_data(self, value):
        try:
            self.data = list(self.coerce(v) for v in value)
        except (ValueError, TypeError):
            self.data = None

    def process_formdata(self, valuelist):
        try:
            self.data = list(self.coerce(x) for x in valuelist)
        except ValueError:
            raise ValueError(self.gettext('Invalid choice(s): one or more data inputs could not be coerced'))

    def pre_validate(self, form):
        if self.data:
            values = list(c[0] for c in self.choices)
            for d in self.data:
                if d not in values:
                    raise ValueError(self.gettext("'%(value)s' is not a valid choice for this field") % dict(value=d))


class RadioField(SelectField):
    """
    Like a SelectField, except displays a list of radio buttons.

    Iterating the field will produce subfields (each containing a label as
    well) in order to allow custom rendering of the individual radio fields.
    """
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.RadioInput()


class StringField(Field):
    """
    This field is the base for most of the more complicated fields, and
    represents an ``<input type="text">``.
    """
    widget = widgets.TextInput()

    def process_formdata(self, valuelist):
        if valuelist:
            self.data = valuelist[0]
        elif self.data is None:
            self.data = ''

    def _value(self):
        return text_type(self.data) if self.data is not None else ''


class LocaleAwareNumberField(Field):
    """
    Base class for implementing locale-aware number parsing.

    Locale-aware numbers require the 'babel' package to be present.
    """
    def __init__(self, label=None, validators=None, use_locale=False, number_format=None, **kwargs):
        super(LocaleAwareNumberField, self).__init__(label, validators, **kwargs)
        self.use_locale = use_locale
        if use_locale:
            self.number_format = number_format
            self.locale = kwargs['_form'].meta.locales[0]
            self._init_babel()

    def _init_babel(self):
        try:
            from babel import numbers
            self.babel_numbers = numbers
        except ImportError:
            raise ImportError('Using locale-aware decimals requires the babel library.')

    def _parse_decimal(self, value):
        return self.babel_numbers.parse_decimal(value, self.locale)

    def _format_decimal(self, value):
        return self.babel_numbers.format_decimal(value, self.number_format, self.locale)


class IntegerField(Field):
    """
    A text field, except all input is coerced to an integer.  Erroneous input
    is ignored and will not be accepted as a value.
    """
    widget = widgets.TextInput()

    def __init__(self, label=None, validators=None, **kwargs):
        super(IntegerField, self).__init__(label, validators, **kwargs)

    def _value(self):
        if self.raw_data:
            return self.raw_data[0]
        elif self.data is not None:
            return text_type(self.data)
        else:
            return ''

    def process_formdata(self, valuelist):
        if valuelist:
            try:
                self.data = int(valuelist[0])
            except ValueError:
                self.data = None
                raise ValueError(self.gettext('Not a valid integer value'))


class DecimalField(LocaleAwareNumberField):
    """
    A text field which displays and coerces data of the `decimal.Decimal` type.

    :param places:
        How many decimal places to quantize the value to for display on form.
        If None, does not quantize value.
    :param rounding:
        How to round the value during quantize, for example
        `decimal.ROUND_UP`. If unset, uses the rounding value from the
        current thread's context.
    :param use_locale:
        If True, use locale-based number formatting. Locale-based number
        formatting requires the 'babel' package.
    :param number_format:
        Optional number format for locale. If omitted, use the default decimal
        format for the locale.
    """
    widget = widgets.TextInput()

    def __init__(self, label=None, validators=None, places=unset_value, rounding=None, **kwargs):
        super(DecimalField, self).__init__(label, validators, **kwargs)
        if self.use_locale and (places is not unset_value or rounding is not None):
            raise TypeError("When using locale-aware numbers, 'places' and 'rounding' are ignored.")

        if places is unset_value:
            places = 2
        self.places = places
        self.rounding = rounding

    def _value(self):
        if self.raw_data:
            return self.raw_data[0]
        elif self.data is not None:
            if self.use_locale:
                return text_type(self._format_decimal(self.data))
            elif self.places is not None:
                if hasattr(self.data, 'quantize'):
                    exp = decimal.Decimal('.1') ** self.places
                    if self.rounding is None:
                        quantized = self.data.quantize(exp)
                    else:
                        quantized = self.data.quantize(exp, rounding=self.rounding)
                    return text_type(quantized)
                else:
                    # If for some reason, data is a float or int, then format
                    # as we would for floats using string formatting.
                    format = '%%0.%df' % self.places
                    return format % self.data
            else:
                return text_type(self.data)
        else:
            return ''

    def process_formdata(self, valuelist):
        if valuelist:
            try:
                if self.use_locale:
                    self.data = self._parse_decimal(valuelist[0])
                else:
                    self.data = decimal.Decimal(valuelist[0])
            except (decimal.InvalidOperation, ValueError):
                self.data = None
                raise ValueError(self.gettext('Not a valid decimal value'))


class FloatField(Field):
    """
    A text field, except all input is coerced to an float.  Erroneous input
    is ignored and will not be accepted as a value.
    """
    widget = widgets.TextInput()

    def __init__(self, label=None, validators=None, **kwargs):
        super(FloatField, self).__init__(label, validators, **kwargs)

    def _value(self):
        if self.raw_data:
            return self.raw_data[0]
        elif self.data is not None:
            return text_type(self.data)
        else:
            return ''

    def process_formdata(self, valuelist):
        if valuelist:
            try:
                self.data = float(valuelist[0])
            except ValueError:
                self.data = None
                raise ValueError(self.gettext('Not a valid float value'))


class BooleanField(Field):
    """
    Represents an ``<input type="checkbox">``. Set the ``checked``-status by using the
    ``default``-option. Any value for ``default``, e.g. ``default="checked"`` puts
    ``checked`` into the html-element and sets the ``data`` to ``True``

    :param false_values:
        If provided, a sequence of strings each of which is an exact match
        string of what is considered a "false" value. Defaults to the tuple
        ``('false', '')``
    """
    widget = widgets.CheckboxInput()
    false_values = (False, 'false', '')

    def __init__(self, label=None, validators=None, false_values=None, **kwargs):
        super(BooleanField, self).__init__(label, validators, **kwargs)
        if false_values is not None:
            self.false_values = false_values

    def process_data(self, value):
        self.data = bool(value)

    def process_formdata(self, valuelist):
        if not valuelist or valuelist[0] in self.false_values:
            self.data = False
        else:
            self.data = True

    def _value(self):
        if self.raw_data:
            return text_type(self.raw_data[0])
        else:
            return 'y'


class DateTimeField(Field):
    """
    A text field which stores a `datetime.datetime` matching a format.
    """
    widget = widgets.TextInput()

    def __init__(self, label=None, validators=None, format='%Y-%m-%d %H:%M:%S', **kwargs):
        super(DateTimeField, self).__init__(label, validators, **kwargs)
        self.format = format

    def _value(self):
        if self.raw_data:
            return ' '.join(self.raw_data)
        else:
            return self.data and self.data.strftime(self.format) or ''

    def process_formdata(self, valuelist):
        if valuelist:
            date_str = ' '.join(valuelist)
            try:
                self.data = datetime.datetime.strptime(date_str, self.format)
            except ValueError:
                self.data = None
                raise ValueError(self.gettext('Not a valid datetime value'))


class DateField(DateTimeField):
    """
    Same as DateTimeField, except stores a `datetime.date`.
    """
    def __init__(self, label=None, validators=None, format='%Y-%m-%d', **kwargs):
        super(DateField, self).__init__(label, validators, format, **kwargs)

    def process_formdata(self, valuelist):
        if valuelist:
            date_str = ' '.join(valuelist)
            try:
                self.data = datetime.datetime.strptime(date_str, self.format).date()
            except ValueError:
                self.data = None
                raise ValueError(self.gettext('Not a valid date value'))


class TimeField(DateTimeField):
    """
    Same as DateTimeField, except stores a `time`.
    """
    def __init__(self, label=None, validators=None, format='%H:%M', **kwargs):
        super(TimeField, self).__init__(label, validators, format, **kwargs)

    def process_formdata(self, valuelist):
        if valuelist:
            time_str = ' '.join(valuelist)
            try:
                self.data = datetime.datetime.strptime(time_str, self.format).time()
            except ValueError:
                self.data = None
                raise ValueError(self.gettext('Not a valid time value'))


class FormField(Field):
    """
    Encapsulate a form as a field in another form.

    :param form_class:
        A subclass of Form that will be encapsulated.
    :param separator:
        A string which will be suffixed to this field's name to create the
        prefix to enclosed fields. The default is fine for most uses.
    """
    widget = widgets.TableWidget()

    def __init__(self, form_class, label=None, validators=None, separator='-', **kwargs):
        super(FormField, self).__init__(label, validators, **kwargs)
        self.form_class = form_class
        self.separator = separator
        self._obj = None
        if self.filters:
            raise TypeError('FormField cannot take filters, as the encapsulated data is not mutable.')
        if validators:
            raise TypeError('FormField does not accept any validators. Instead, define them on the enclosed form.')

    def process(self, formdata, data=unset_value):
        if data is unset_value:
            try:
                data = self.default()
            except TypeError:
                data = self.default
            self._obj = data

        self.object_data = data

        prefix = self.name + self.separator
        if isinstance(data, dict):
            self.form = self.form_class(formdata=formdata, prefix=prefix, **data)
        else:
            self.form = self.form_class(formdata=formdata, obj=data, prefix=prefix)

    def validate(self, form, extra_validators=tuple()):
        if extra_validators:
            raise TypeError('FormField does not accept in-line validators, as it gets errors from the enclosed form.')
        return self.form.validate()

    def populate_obj(self, obj, name):
        candidate = getattr(obj, name, None)
        if candidate is None:
            if self._obj is None:
                raise TypeError('populate_obj: cannot find a value to populate from the provided obj or input data/defaults')
            candidate = self._obj
            setattr(obj, name, candidate)

        self.form.populate_obj(candidate)

    def __iter__(self):
        return iter(self.form)

    def __getitem__(self, name):
        return self.form[name]

    def __getattr__(self, name):
        return getattr(self.form, name)

    @property
    def data(self):
        return self.form.data

    @property
    def errors(self):
        return self.form.errors


class FieldList(Field):
    """
    Encapsulate an ordered list of multiple instances of the same field type,
    keeping data as a list.

    >>> authors = FieldList(StringField('Name', [validators.required()]))

    :param unbound_field:
        A partially-instantiated field definition, just like that would be
        defined on a form directly.
    :param min_entries:
        if provided, always have at least this many entries on the field,
        creating blank ones if the provided input does not specify a sufficient
        amount.
    :param max_entries:
        accept no more than this many entries as input, even if more exist in
        formdata.
    """
    widget = widgets.ListWidget()

    def __init__(self, unbound_field, label=None, validators=None, min_entries=0,
                 max_entries=None, default=tuple(), **kwargs):
        super(FieldList, self).__init__(label, validators, default=default, **kwargs)
        if self.filters:
            raise TypeError('FieldList does not accept any filters. Instead, define them on the enclosed field.')
        assert isinstance(unbound_field, UnboundField), 'Field must be unbound, not a field class'
        self.unbound_field = unbound_field
        self.min_entries = min_entries
        self.max_entries = max_entries
        self.last_index = -1
        self._prefix = kwargs.get('_prefix', '')

    def process(self, formdata, data=unset_value):
        self.entries = []
        if data is unset_value or not data:
            try:
                data = self.default()
            except TypeError:
                data = self.default

        self.object_data = data

        if formdata:
            indices = sorted(set(self._extract_indices(self.name, formdata)))
            if self.max_entries:
                indices = indices[:self.max_entries]

            idata = iter(data)
            for index in indices:
                try:
                    obj_data = next(idata)
                except StopIteration:
                    obj_data = unset_value
                self._add_entry(formdata, obj_data, index=index)
        else:
            for obj_data in data:
                self._add_entry(formdata, obj_data)

        while len(self.entries) < self.min_entries:
            self._add_entry(formdata)

    def _extract_indices(self, prefix, formdata):
        """
        Yield indices of any keys with given prefix.

        formdata must be an object which will produce keys when iterated.  For
        example, if field 'foo' contains keys 'foo-0-bar', 'foo-1-baz', then
        the numbers 0 and 1 will be yielded, but not neccesarily in order.
        """
        offset = len(prefix) + 1
        for k in formdata:
            if k.startswith(prefix):
                k = k[offset:].split('-', 1)[0]
                if k.isdigit():
                    yield int(k)

    def validate(self, form, extra_validators=tuple()):
        """
        Validate this FieldList.

        Note that FieldList validation differs from normal field validation in
        that FieldList validates all its enclosed fields first before running any
        of its own validators.
        """
        self.errors = []

        # Run validators on all entries within
        for subfield in self.entries:
            if not subfield.validate(form):
                self.errors.append(subfield.errors)

        chain = itertools.chain(self.validators, extra_validators)
        self._run_validation_chain(form, chain)

        return len(self.errors) == 0

    def populate_obj(self, obj, name):
        values = getattr(obj, name, None)
        try:
            ivalues = iter(values)
        except TypeError:
            ivalues = iter([])

        candidates = itertools.chain(ivalues, itertools.repeat(None))
        _fake = type(str('_fake'), (object, ), {})
        output = []
        for field, data in izip(self.entries, candidates):
            fake_obj = _fake()
            fake_obj.data = data
            field.populate_obj(fake_obj, 'data')
            output.append(fake_obj.data)

        setattr(obj, name, output)

    def _add_entry(self, formdata=None, data=unset_value, index=None):
        assert not self.max_entries or len(self.entries) < self.max_entries, \
            'You cannot have more than max_entries entries in this FieldList'
        if index is None:
            index = self.last_index + 1
        self.last_index = index
        name = '%s-%d' % (self.short_name, index)
        id = '%s-%d' % (self.id, index)
        field = self.unbound_field.bind(form=None, name=name, prefix=self._prefix, id=id, _meta=self.meta,
                                        translations=self._translations)
        field.process(formdata, data)
        self.entries.append(field)
        return field

    def append_entry(self, data=unset_value):
        """
        Create a new entry with optional default data.

        Entries added in this way will *not* receive formdata however, and can
        only receive object data.
        """
        return self._add_entry(data=data)

    def pop_entry(self):
        """ Removes the last entry from the list and returns it. """
        entry = self.entries.pop()
        self.last_index -= 1
        return entry

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, index):
        return self.entries[index]

    @property
    def data(self):
        return [f.data for f in self.entries]