"""
Custom Authenticator to use GitLab OAuth with JupyterHub

Developed at BT by William Harmer (@harmer_will)
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator, LocalAuthenticator
from jupyterhub.utils import url_path_join

from IPython.utils.traitlets import Unicode

class GitLabMixin(OAuth2Mixin):
    gitlab_host = Unicode(os.environ.get('GITLAB_HOST_URL', ''))
    _OAUTH_AUTHORIZE_URL = "{0}/oauth/authorize".format(gitlab_host)
    _OAUTH_ACCESS_TOKEN_URL = "{0}/oauth/token".format(gitlab_host)

class GitLabLoginHandler(BaseHandler, GitHubMixin):
    def get(self):
        guess_uri = '{proto}://{host}{path}'.format(
            proto=self.request.protocol,
            host=self.request.host,
            path=url_path_join(
                self.hub.server.base_url,
                'oauth_callback'
            )
        )
        
        redirect_uri = self.authenticator.oauth_callback_url or guess_uri
        self.log.info('oauth redirect: %r', redirect_uri)
        
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.gitlab_client_id,
            scope=[],
            response_type='code')


class GitLabOAuthHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        # TODO: Check if state argument needs to be checked
        username = yield self.authenticator.authenticate(self)
        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error page?
            raise web.HTTPError(403)


class GitLabOAuthenticator(Authenticator):
    
    login_service = "GitLab"
    oauth_callback_url = Unicode('', config=True)
    gitlab_client_id = Unicode(os.environ.get('GITLAB_CLIENT_ID', ''),
        config=True)
    gitlab_client_secret = Unicode(os.environ.get('GITLAB_CLIENT_SECRET', ''),
        config=True)
    
    def login_url(self, base_url):
        return url_path_join(base_url, 'oauth_login')
    
    def get_handlers(self, app):
        return [
            (r'/oauth_login', GitLabLoginHandler),
            (r'/oauth_callback', GitLabOAuthHandler),
        ]
    
    @gen.coroutine
    def authenticate(self, handler):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()
        
        # Exchange the OAuth code for a GitLab Access Token
        #
        # See: http://doc.gitlab.com/ce/api/oauth2.html
        
        # GitLab specifies a POST request yet requires URL parameters
        params = dict(
                client_id=self.gitlab_client_id,
                client_secret=self.gitlab_client_secret,
                code=code
        )
        
        url = url_concat("{0}/oauth/token".format(gitlab_host),
                         params)
        
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "token {}".format(access_token)
        }
        req = HTTPRequest("{0}/user".format(gitlab_host),
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        username = resp_json["login"]
        if self.whitelist and username not in self.whitelist:
            username = None
        raise gen.Return(username)


class LocalGitLabOAuthenticator(LocalAuthenticator, GitLabOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
