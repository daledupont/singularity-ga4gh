"""
The Flask frontend for the GA4GH API.

TODO Document properly.
"""
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import datetime
import socket
import urlparse
import functools
import json

import flask
import flask.ext.cors as cors
from flask import request
from flask.ext.oidc import OpenIDConnect
import humanize
import werkzeug
import oic
import oic.oauth2
import oic.oic.message as message
from oauth2client.client import OAuth2Credentials
import requests
import logging
from logging import StreamHandler
from werkzeug.contrib.cache import FileSystemCache

import ga4gh.server
import ga4gh.server.backend as backend
import ga4gh.server.datamodel as datamodel
import ga4gh.server.exceptions as exceptions
import ga4gh.server.datarepo as datarepo
import ga4gh.server.auth as auth
import ga4gh.server.network as network
import ga4gh.schemas.protocol as protocol

MIMETYPE = "application/json"
SEARCH_ENDPOINT_METHODS = ['POST', 'OPTIONS']
SECRET_KEY_LENGTH = 24

req = request

app = flask.Flask(__name__)

assert not hasattr(app, 'urls')
app.urls = []
requires_auth = auth.auth_decorator(app)

# Edit this for flask-oidc, the endpoints are in the client_secrets.json file
app.config.update({
    'SECRET_KEY': "key",
    'TESTING': False,
    'DEBUG': False,
    'OIDC_CLIENT_SECRETS': '/srv/ga4gh-server/client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_OPENID_REALM': 'http://142.1.33.237:8000/oidc_callback'
    # Change host and port
})

# For configuration of Flask-Oidc
oidc = OpenIDConnect(app)


class NoConverter(werkzeug.routing.BaseConverter):
    """
    A converter that allows the routing matching algorithm to not
    match on certain literal terms

    This is needed because if there are e.g. two routes:

    /callsets/search
    /callsets/<id>

    A request for /callsets/search will get routed to
    the second, which is not what we want.
    """
    def __init__(self, map, *items):
        werkzeug.routing.BaseConverter.__init__(self, map)
        self.items = items

    def to_python(self, value):
        if value in self.items:
            raise werkzeug.routing.ValidationError()
        return value


app.url_map.converters['no'] = NoConverter


class ServerStatus(object):
    """
    Generates information about the status of the server for display
    """
    def __init__(self):
        self.startupTime = datetime.datetime.now()

    def getConfiguration(self):
        """
        Returns a list of configuration (key, value) tuples
        that are useful for users to view on an information page.
        Note that we should be careful here not to leak sensitive
        information. For example, keys and paths of data files should
        not be returned.
        """
        # TODO what other config keys are appropriate to export here?
        keys = [
            'DEBUG', 'REQUEST_VALIDATION', 'DEFAULT_PAGE_SIZE',
            'MAX_RESPONSE_LENGTH', 'LANDING_MESSAGE_HTML'
        ]

        return [(k, app.config[k]) for k in keys]

    def getPreciseUptime(self):
        """
        Returns the server precisely.
        """
        return self.startupTime.strftime("%H:%M:%S %d %b %Y")

    def getLandingMessageHtml(self):
        filePath = app.config.get('LANDING_MESSAGE_HTML')
        try:
            htmlFile = open(filePath, 'r')
            html = htmlFile.read()
            htmlFile.close()
        except:
            html = flask.render_template("landing_message.html")
        return html

    def getNaturalUptime(self):
        """
        Returns the uptime in a human-readable format.
        """
        return humanize.naturaltime(self.startupTime)

    def getProtocolVersion(self):
        """
        Returns the GA4GH protocol version we support.
        """
        return protocol.version

    def getServerVersion(self):
        """
        Returns the software version of this server.
        """
        return ga4gh.server.__version__

    def getUrls(self):
        """
        Returns the list of (httpMethod, URL) tuples
        that this server supports.
        """
        app.urls.sort()
        return app.urls

    def getDatasets(self):
        """
        Returns the list of datasetIds for this backend
        """
        return app.backend.getDataRepository().getDatasets()

    def getVariantSets(self, datasetId):
        """
        Returns the list of variant sets for the dataset
        """
        repo = app.backend.getDataRepository()
        return repo.getDataset(datasetId).getVariantSets()

    def getFeatureSets(self, datasetId):
        """
        Returns the list of feature sets for the dataset
        """
        repo = app.backend.getDataRepository()
        return repo.getDataset(datasetId).getFeatureSets()

    def getContinuousSets(self, datasetId):
        """
        Returns the list of continuous sets for the dataset
        """
        repo = app.backend.getDataRepository()
        return repo.getDataset(datasetId).getContinuousSets()

    def getReadGroupSets(self, datasetId):
        """
        Returns the list of ReadGroupSets for the dataset
        """
        repo = app.backend.getDataRepository()
        return repo.getDataset(datasetId).getReadGroupSets()

    def getReferenceSets(self):
        """
        Returns the list of ReferenceSets for this server.
        """
        repo = app.backend.getDataRepository()
        return repo.getReferenceSets()

    def getVariantAnnotationSets(self, datasetId):
        """
        Returns the list of ReferenceSets for this server.
        """
        # TODO this should be displayed per-variant set, not per dataset.
        variantAnnotationSets = []
        repo = app.backend.getDataRepository()
        dataset = repo.getDataset(datasetId)
        for variantSet in dataset.getVariantSets():
            variantAnnotationSets.extend(
                variantSet.getVariantAnnotationSets())
        return variantAnnotationSets

    def getPhenotypeAssociationSets(self, datasetId):
        repo = app.backend.getDataRepository()
        return repo.getDataset(datasetId).getPhenotypeAssociationSets()

    def getRnaQuantificationSets(self, datasetId):
        """Returns the list of RnaQuantificationSets for this server."""
        repo = app.backend.getDataRepository()
        return repo.getDataset(datasetId).getRnaQuantificationSets()


def reset():
    """
    Resets the flask app; used in testing
    """
    app.config.clear()
    configStr = 'ga4gh.server.serverconfig:FlaskDefaultConfig'
    app.config.from_object(configStr)


def _configure_backend(app):
    """
    A helper function used just to help modularize the code a bit.
    """
    # Allocate the backend
    # We use URLs to specify the backend. Currently we have file:// URLs (or
    # URLs with no scheme) for the SqlDataRepository, and special empty:// and
    # simulated:// URLs for empty or simulated data sources.
    dataSource = urlparse.urlparse(app.config["DATA_SOURCE"], "file")

    if dataSource.scheme == "simulated":
        # Ignore the query string
        randSeedField = "SIMULATED_BACKEND_RANDOM_SEED"
        numCallField = "SIMULATED_BACKEND_NUM_CALLS"
        varDensField = "SIMULATED_BACKEND_VARIANT_DENSITY"
        numVarField = "SIMULATED_BACKEND_NUM_VARIANT_SETS"
        numRefField = "SIMULATED_BACKEND_NUM_REFERENCE_SETS"
        refRatField = "SIMULATED_BACKEND_NUM_REFERENCES_PER_REFERENCE_SET"
        alignGrpField = "SIMULATED_BACKEND_NUM_ALIGNMENTS_PER_READ_GROUP"
        grpRatGrpField = "SIMULATED_BACKEND_NUM_READ_GROUPS_PER_READ_GROUP_SET"
        phenoAssocField = "SIMULATED_BACKEND_NUM_PHENOTYPE_ASSOCIATIONS"
        phenoSetField = "SIMULATED_BACKEND_NUM_PHENOTYPE_ASSOCIATION_SETS"
        rnaQuantField = "SIMULATED_BACKEND_NUM_RNA_QUANTIFICATION_SETS"
        exprField = "SIMULATED_BACKEND_NUM_EXPRESSION_LEVELS_PER_RNA_QUANT_SET"

        randomSeed = app.config[randSeedField]
        numCalls = app.config[numCallField]
        variantDensity = app.config[varDensField]
        numVariantSets = app.config[numVarField]
        numReferenceSets = app.config[numRefField]
        numReferencesPerReferenceSet = app.config[refRatField]
        numAlignmentsPerReadGroup = app.config[alignGrpField]
        numReadGroupsPerReadGroupSet = app.config[grpRatGrpField]
        numPhenotypeAssociations = app.config[phenoAssocField]
        numPhenotypeAssociationSets = app.config[phenoSetField]
        numRnaQuantSets = app.config[rnaQuantField]
        numExpressionLevels = app.config[exprField]

        dataRepository = datarepo.SimulatedDataRepository(
            randomSeed=randomSeed, numCalls=numCalls,
            variantDensity=variantDensity, numVariantSets=numVariantSets,
            numReferenceSets=numReferenceSets,
            numReferencesPerReferenceSet=numReferencesPerReferenceSet,
            numReadGroupsPerReadGroupSet=numReadGroupsPerReadGroupSet,
            numAlignments=numAlignmentsPerReadGroup,
            numPhenotypeAssociations=numPhenotypeAssociations,
            numPhenotypeAssociationSets=numPhenotypeAssociationSets,
            numRnaQuantSets=numRnaQuantSets,
            numExpressionLevels=numExpressionLevels)
    elif dataSource.scheme == "empty":
        dataRepository = datarepo.EmptyDataRepository()
    elif dataSource.scheme == "file":
        path = os.path.join(dataSource.netloc, dataSource.path)
        dataRepository = datarepo.SqlDataRepository(path)
        dataRepository.open(datarepo.MODE_READ)
    else:
        raise exceptions.ConfigurationException(
            "Unsupported data source scheme: " + dataSource.scheme)

    theBackend = backend.Backend(dataRepository)
    theBackend.setRequestValidation(app.config["REQUEST_VALIDATION"])
    theBackend.setDefaultPageSize(app.config["DEFAULT_PAGE_SIZE"])
    theBackend.setMaxResponseLength(app.config["MAX_RESPONSE_LENGTH"])
    return theBackend


def configure(configFile=None, baseConfig="ProductionConfig",
              port=8000, extraConfig={}):
    """
    TODO Document this critical function! What does it do? What does
    it assume?

    Based on the configuration the server is being hosted with,
    it initalizes all the variables needed, and generates
    the redirect-url for the Auth and OIDC providers
    (if present).
    """
    file_handler = StreamHandler()
    file_handler.setLevel(logging.WARNING)
    app.logger.addHandler(file_handler)
    configStr = 'ga4gh.server.serverconfig:{0}'.format(baseConfig)
    app.config.from_object(configStr)

    if os.environ.get('GA4GH_CONFIGURATION') is not None:
        app.config.from_envvar('GA4GH_CONFIGURATION')

    if configFile is not None:
        app.config.from_pyfile(configFile)

    app.config.update(extraConfig.items())

    # Setup file handle cache max size
    datamodel.fileHandleCache.setMaxCacheSize(
        app.config["FILE_HANDLE_CACHE_MAX_SIZE"])

    # Setup CORS
    try:
        cors.CORS(app, allow_headers='Content-Type')
    except AssertionError:
        pass

    app.serverStatus = ServerStatus()
    app.backend = _configure_backend(app)

    if app.config.get('SECRET_KEY'):
        app.secret_key = app.config['SECRET_KEY']
    elif app.config.get('OIDC_PROVIDER'):
        raise exceptions.ConfigurationException(
            'OIDC configuration requires a secret key')

    if app.config.get('CACHE_DIRECTORY'):
        app.cache_dir = app.config['CACHE_DIRECTORY']
    else:
        app.cache_dir = '/tmp/ga4gh'

    app.cache = FileSystemCache(app.cache_dir, threshold=5000,
                                default_timeout=600, mode=384)

    # Peer service initialization
    network.initialize(app.config.get('INITIAL_PEERS'),
                       app.backend.getDataRepository(),
                       app.logger)
    app.oidcClient = None
    app.myPort = port

    if app.config.get('AUTH0_ENABLED'):
        emails = app.config.get('AUTH0_AUTHORIZED_EMAILS', '').split(',')
        [auth.authorize_email(e, app.cache) for e in emails]

    if "OIDC_PROVIDER" in app.config:
        # The oic client. If we're testing, we don't want to verify
        # SSL certificates
        app.oidcClient = oic.oic.Client(
            verify_ssl=('TESTING' not in app.config))
        try:
            app.oidcClient.provider_config(app.config['OIDC_PROVIDER'])
        except requests.exceptions.ConnectionError:
            configResponse = message.ProviderConfigurationResponse(
                issuer=app.config['OIDC_PROVIDER'],
                authorization_endpoint=app.config['OIDC_AUTHZ_ENDPOINT'],
                token_endpoint=app.config['OIDC_TOKEN_ENDPOINT'],
                revocation_endpoint=app.config['OIDC_TOKEN_REV_ENDPOINT'])
            app.oidcClient.handle_provider_config(configResponse,
                                                  app.config['OIDC_PROVIDER'])

        # The redirect URI comes from the configuration.
        # If we are testing, then we allow the automatic creation of a
        # redirect uri if none is configured
        redirectUri = app.config.get('OIDC_REDIRECT_URI')

        if redirectUri is None:
            uriStr = 'https://{0}:{1}/oauth2callback'
            redirectUri = uriStr.format(socket.gethostname(), app.myPort)

        app.oidcClient.redirect_uris = [redirectUri]

        if redirectUri is []:
            errMsg = 'OIDC configuration requires a redirect uri'
            raise exceptions.ConfigurationException(errMsg)

        print(redirectUri)

        # We only support dynamic registration while testing.

        if ('registration_endpoint' in app.oidcClient.provider_info):
            app.oidcClient.register(
                app.oidcClient.provider_info["registration_endpoint"],
                redirect_uris=[redirectUri])
        else:
            response = message.RegistrationResponse(
                client_id=app.config['OIDC_CLIENT_ID'],
                client_secret=app.config['OIDC_CLIENT_SECRET'],
                redirect_uris=[redirectUri],
                verify_ssl=False)
            app.oidcClient.store_registration_info(response)


def getFlaskResponse(responseString, httpStatus=200):
    """
    Returns a Flask response object for the specified data and HTTP status.
    """
    return flask.Response(responseString, status=httpStatus, mimetype=MIMETYPE)


def handleHttpPost(request, endpoint):
    """
    Handles the specified HTTP POST request, which maps to the specified
    protocol handler endpoint and protocol request class.
    """
    if request.mimetype and request.mimetype != MIMETYPE:
        raise exceptions.UnsupportedMediaTypeException()

    request = request.get_data()

    if request == '' or request is None:
        request = '{}'

    responseStr = endpoint(request)
    return getFlaskResponse(responseStr)


def handleList(endpoint, request):
    """
    Handles the specified HTTP GET request, mapping to a list request
    """
    responseStr = endpoint(request.get_data())
    return getFlaskResponse(responseStr)


def handleHttpGet(id_, endpoint):
    """
    Handles the specified HTTP GET request, which maps to the specified
    protocol handler endpoint and protocol request class
    """
    responseStr = endpoint(id_)
    return getFlaskResponse(responseStr)


def handleHttpOptions():
    """
    Handles the specified HTTP OPTIONS request.
    """
    response = getFlaskResponse("")
    response.headers.add("Access-Control-Request-Methods", "GET,POST,OPTIONS")
    return response


@app.errorhandler(Exception)
def handleException(exception):
    """
    Handles an exception that occurs somewhere in the process of handling
    a request.
    """
    serverException = exception

    if not isinstance(exception, exceptions.BaseServerException):
        with app.test_request_context():
            app.log_exception(exception)
        serverException = exceptions.getServerError(exception)

    error = serverException.toProtocolElement()

    # If the exception is being viewed by a web browser,
    # we can render a nicer view.
    if req and 'Accept' in req.headers and \
            req.headers['Accept'].find('text/html') != -1:
        errStr = "<h1>Error {}</h1><pre>{}</pre>"
        message = errStr.format(serverException.httpStatus,
                                protocol.toJson(error))
        if serverException.httpStatus == 401 \
                or serverException.httpStatus == 403:
            message += "Please try <a href=\"/login\">logging in</a>."
        return message
    else:
        responseStr = protocol.toJson(error)
        return getFlaskResponse(responseStr, serverException.httpStatus)


# Added by Kevin Chan
def requires_token(f):
    """
    Decorator function that ensures that the token is valid,
    if the token is invalid or expired, the user will be
    redirected to the login page. Much of the authorization
    code flow is done solely by the function decorator
    @oidc.require_login
    """
    @functools.wraps(f)
    def decorated(*args, **kargs):
        if app.config.get("KEYCLOAK"):
            targetSocket = socket.gethostbyname(socket.gethostname())
            redirectUri = 'http://{0}:{1}{2}'.format(
                    targetSocket, app.myPort, req.path)
            try:
                info = oidc.user_getinfo(['sub'])
                creds = oidc.credentials_store[info.get('sub')]
                cred = OAuth2Credentials
                jsonCred = cred.from_json(creds)
                tokenResponse = jsonCred.token_response
                introspectArgs = {
                    "token": tokenResponse["access_token"],
                    "client_id": oidc.client_secrets["client_id"],
                    "client_secret": oidc.client_secrets["client_secret"],
                    "refresh_token": tokenResponse["refresh_token"],
                }
            except:
                return flask.redirect(redirectUri)
            tokIntroUri = oidc.client_secrets["token_introspection_uri"]
            userInfo = requests.post(url=tokIntroUri, data=introspectArgs)

            if userInfo.status_code != 200:
                raise exceptions.NotAuthenticatedException()
        return f(*args, **kargs)
    return decorated


def startLogin():
    """
    If user is not logged in,
    this generates the redirect URL to the OIDC or Auth
    provider (depending on the configuration)
    Returns: the redirect response
    """
    provInfo = app.oidcClient.provider_info
    flask.session["state"] = oic.oauth2.rndstr(SECRET_KEY_LENGTH)
    flask.session["nonce"] = oic.oauth2.rndstr(SECRET_KEY_LENGTH)
    args = {
        "client_id": app.oidcClient.client_id,
        "response_type": "code",
        "scope": ["openid", "profile"],
        "nonce": flask.session["nonce"],
        "redirect_uri": app.oidcClient.redirect_uris[0],
        "authorization_endpoint": provInfo["authorization_endpoint"],
        "state": flask.session["state"],
    }

    # First condition is the configuration for the Keycloak Server.
    # Redirects the user to the Keycloak sign in page.
    # I left this here for your reference.
    # Added by Kevin Chan

    if "WELL_KNOWN_CONFIG" in app.config:
        # result = app.oidcClient.do_authorization_request(
        # request_args=args, state=flask.session["state"])
        oidcApp = app.oidcClient
        result = oidcApp.construct_AuthorizationRequest(request_args=args)
        addOn = result.request(app.oidcClient.authorization_endpoint)
        loginUrl = provInfo["authorization_endpoint"] + addOn

        if req.path == "/login":
            flask.session["path"] = "/"
        else:
            flask.session["path"] = req.path
        return flask.redirect(loginUrl)

    result = app.oidcClient.do_authorization_request(
             request_args=args, state=flask.session["state"])
    return flask.redirect(result.url)


def handleFlaskGetRequest(id_, flaskRequest, endpoint):
    """
    Handles the specified flask request for one of the GET URLs
    Invokes the specified endpoint to generate a response.
    """
    if flaskRequest.method == "GET":
        return handleHttpGet(id_, endpoint)
    else:
        raise exceptions.MethodNotAllowedException()


def handleFlaskListRequest(id_, flaskRequest, endpoint):
    """
    Handles the specified flask list request for one of the GET URLs.
    Invokes the specified endpoint to generate a response.
    """

    return handleList(endpoint, flaskRequest)


def handleFlaskPostRequest(flaskRequest, endpoint):
    """
    Handles the specified flask request for one of the POST URLS
    Invokes the specified endpoint to generate a response.
    """
    if flaskRequest.method == "POST":
        return handleHttpPost(flaskRequest, endpoint)
    elif flaskRequest.method == "OPTIONS":
        return handleHttpOptions()
    else:
        raise exceptions.MethodNotAllowedException()


class DisplayedRoute(object):
    """
    Registers that a route should be displayed on the html page
    """
    def __init__(
            self, path, postMethod=False, pathDisplay=None):
        self.path = path
        self.methods = None

        if postMethod:
            methodDisplay = 'POST'
            self.methods = SEARCH_ENDPOINT_METHODS
        else:
            methodDisplay = 'GET'

        if pathDisplay is None:
            pathDisplay = path

        app.urls.append((methodDisplay, pathDisplay))

    def __call__(self, func):
        if self.methods is None:
            app.add_url_rule(self.path, func.func_name, func)
        else:
            app.add_url_rule(
                self.path, func.func_name, func, methods=self.methods)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            return result
        return wrapper


@app.route('/')
@oidc.require_login
@requires_token
def index():
    response = flask.render_template('index.html',
                                     info=app.serverStatus)
    if app.config.get('AUTH0_ENABLED'):
        key = (req.args.get('key'))
        try:
            print(key)
            profile = app.cache.get(key)
        except:
            raise exceptions.NotAuthorizedException()

        if (profile):
            return response
        else:
            exceptions.NotAuthenticatedException()
    else:
        return response


# New configuration added by Kevin Chan
@app.route("/login")
def login():
    conf = app.config

    if conf.get('AUTH0_ENABLED'):

        if (req.args.get('code')):
            return auth.render_key(app, key=req.args.get('code'))
        else:
            authScope = conf.get('AUTH0_SCOPES')
            callback = conf.get('AUTH0_CALLBACK_URL')
            host = conf.get('AUTH0_HOST')
            cliId = conf.get('AUTH0_CLIENT_ID')
            return auth.render_login(
                app=app, scopes=authScope,
                redirect_uri=callback,
                domain=host, client_id=cliId)

    # Configuration for KeyCloak Server
    elif conf.get('KEYCLOAK'):
        app.oidClient = None
        flask.session.clear()
        return startLogin()

    else:
        raise exceptions.NotFoundException()


@app.route('/callback')
def callback_handling():
    conf = app.config

    if app.config.get('AUTH0_ENABLED'):
        return auth.callback_maker(
            cache=app.cache,
            domain=conf.get('AUTH0_HOST'),
            client_id=conf.get('AUTH0_CLIENT_ID'),
            client_secret=conf.get('AUTH0_CLIENT_SECRET'),
            redirect_uri=conf.get('AUTH0_CALLBACK_URL'))()
    else:
        raise exceptions.NotFoundException()


@app.route("/logout")
@requires_auth
@cors.cross_origin(headers=['Content-Type', 'Authorization'])
def logout():
    conf = app.config

    if conf.get('AUTH0_ENABLED'):
        key = flask.session['auth0_key']
        auth.logout(app.cache)
        urlStr = 'https://{}/v2/logout?access_token={}&?client_id={}'
        url = urlStr.format(conf.get('AUTH0_HOST'), key,
                            conf.get('AUTH0_CLIENT_ID'),
                            conf.get('AUTH0_CALLBACK_URL'))
        return flask.redirect(url)
    else:
        targetUrl = app.oidcClient.provider_info["session_endpoint"]
        flask.session.clear()
        targetSocket = socket.gethostbyname(socket.gethostname())
        urlStr = "http://{0}:{1}"
        targetUrl = urlStr.format(targetSocket, app.myPort)
        return flask.redirect(targetUrl)


@app.route('/favicon.ico')
@app.route('/robots.txt')
def robots():
    return flask.send_from_directory(
        app.static_folder, req.path[1:])


@DisplayedRoute('/info')
@requires_auth
@oidc.require_login
def getInfo():
    endpoint = app.backend.runGetInfo
    return handleFlaskGetRequest(None, req, endpoint)


@DisplayedRoute('/references/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getReference(id):
    endpoint = app.backend.runGetReference
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute('/referencesets/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getReferenceSet(id):
    endpoint = app.backend.runGetReferenceSet
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute('/listreferencebases', postMethod=True)
def listReferenceBases():
    endpoint = app.backend.runListReferenceBases
    return handleFlaskListRequest(id, req, endpoint)


@DisplayedRoute('/callsets/search', postMethod=True)
def searchCallSets():
    endpoint = app.backend.runSearchCallSets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/readgroupsets/search', postMethod=True)
def searchReadGroupSets():
    endpoint = app.backend.runSearchReadGroupSets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/reads/search', postMethod=True)
def searchReads():
    endpoint = app.backend.runSearchReads
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/referencesets/search', postMethod=True)
def searchReferenceSets():
    endpoint = app.backend.runSearchReferenceSets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/references/search', postMethod=True)
def searchReferences():
    endpoint = app.backend.runSearchReferences
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/variantsets/search', postMethod=True)
def searchVariantSets():
    endpoint = app.backend.runSearchVariantSets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/variants/search', postMethod=True)
def searchVariants():
    endpoint = app.backend.runSearchVariants
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/variantannotationsets/search', postMethod=True)
def searchVariantAnnotationSets():
    endpoint = app.backend.runSearchVariantAnnotationSets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/variantannotations/search', postMethod=True)
def searchVariantAnnotations():
    endpoint = app.backend.runSearchVariantAnnotations
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/datasets/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchDatasets():
    endpoint = app.backend.runSearchDatasets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/featuresets/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchFeatureSets():
    endpoint = app.backend.runSearchFeatureSets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/features/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchFeatures():
    endpoint = app.backend.runSearchFeatures
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/continuoussets/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchContinuousSets():
    endpoint = app.backend.runSearchContinuousSets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/continuous/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchContinuous():
    endpoint = app.backend.runSearchContinuous
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/biosamples/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchBiosamples():
    endpoint = app.backend.runSearchBiosamples
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/individuals/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchIndividuals():
    endpoint = app.backend.runSearchIndividuals
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/peers/list', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def listPeers():
    endpoint = app.backend.runListPeers
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/announce', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def announce():
    # We can't use the post handler here
    # because we want detailed request data.
    return app.backend.runAddAnnouncement(req)


@DisplayedRoute(
    '/biosamples/<no(search):id>',
    pathDisplay='/biosamples/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getBiosample(id):
    endpoint = app.backend.runGetBiosample
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute(
    '/individuals/<no(search):id>',
    pathDisplay='/individuals/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getIndividual(id):
    endpoint = app.backend.runGetIndividual
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute('/rnaquantificationsets/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchRnaQuantificationSets():
    endpoint = app.backend.runSearchRnaQuantificationSets
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/rnaquantifications/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchRnaQuantifications():
    endpoint = app.backend.runSearchRnaQuantifications
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute('/expressionlevels/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchExpressionLevels():
    endpoint = app.backend.runSearchExpressionLevels
    return handleFlaskPostRequest(req, endpoint)


@DisplayedRoute(
    '/variantsets/<no(search):id>',
    pathDisplay='/variantsets/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getVariantSet(id):
    endpoint = app.backend.runGetVariantSet
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute(
    '/variants/<no(search):id>',
    pathDisplay='/variants/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getVariant(id):
    endpoint = app.backend.runGetVariant
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute('/readgroups/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getReadGroup(id):
    endpoint = app.backend.runSearchExpressionLevels
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute(
    '/callsets/<no(search):id>',
    pathDisplay='/callsets/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getCallSet(did):
    endpoint = app.backend.runGetCallSet
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute(
    '/featuresets/<no(search):id>',
    pathDisplay='/featuresets/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getFeatureSet(id):
    endpoint = app.backend.runGetFeatureSet
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute(
    '/features/<no(search):id>',
    pathDisplay='/features/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getFeature(id):
    endpoint = app.backend.runGetFeature
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute(
    '/continuoussets/<no(search):id>',
    pathDisplay='/continuoussets/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getcontinuousSet(id):
    endpoint = app.backend.runGetContinuousSet
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute(
    '/rnaquantificationsets/<no(search):id>',
    pathDisplay='/rnaquantificationsets/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getRnaQuantificationSet(id):
    endpoint = app.backend.runGetRnaQuantificationSet
    return handleFlaskGetRequest(
        id, req, endpoint)


@DisplayedRoute(
    '/rnaquantifications/<no(search):id>',
    pathDisplay='/rnaquantifications/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getRnaQuantification(id):
    endpoint = app.backend.runGetRnaQuantification
    return handleFlaskGetRequest(id, req, endpoint)


@DisplayedRoute(
    '/expressionlevels/<no(search):id>',
    pathDisplay='/expressionlevels/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getExpressionLevel(id):
    endpoint = app.backend.runGetExpressionLevel
    return handleFlaskGetRequest(id, req, endpoint)


@app.route('/oauth2callback', methods=['GET'])
def oidcCallback():
    """
    Once the authorization provider has cleared the user, the browser
    is returned here with a code. This function takes that code and
    checks it with the authorization provider to prove that it is valid,
    and get a bit more information about the user (which we don't use).

    A token is generated and given to the user, and the authorization info
    retrieved above is stored against this token. Later, when a client
    connects with this token, it is assumed to be a valid user.

    :return: A display of the authentication token to use in the client.
    If OIDC is not configured, raises a NotImplementedException.
    """
    if app.oidcClient is None:
        raise exceptions.NotImplementedException()

    response = dict(req.args.iteritems(multi=True))
    aresp = app.oidcClient.parse_response(
        message.AuthorizationResponse,
        info=response,
        sformat='dict')
    sessState = flask.session.get('state')
    respState = aresp['state']
    inst = isinstance(aresp, message.AuthorizationResponse)

    if (not inst or respState != sessState):
        raise exceptions.NotAuthenticatedException()

    args = {
        "code": aresp['code'],
        "redirect_uri": app.oidcClient.redirect_uris[0],
        "client_id": app.oidcClient.client_id,
        "client_secret": app.oidcClient.client_secret
    }

    atr = app.oidcClient.do_access_token_request(
        scope="openid",
        state=respState,
        request_args=args)

    if not isinstance(atr, message.AccessTokenResponse):
        raise exceptions.NotAuthenticatedException()

    atrDict = atr.to_dict()

    if flask.session.get('nonce') != atrDict['id_token']['nonce']:
        raise exceptions.NotAuthenticatedException()

    key = oic.oauth2.rndstr(SECRET_KEY_LENGTH)
    flask.session['key'] = key
    token_data = aresp["code"], respState, atrDict
    app.cache.set(key, token_data)
    # flask.url_for is broken. It relies on SERVER_NAME for both name
    # and port, and defaults to 'localhost' if not found. Therefore
    # we need to fix the returned url
    indexUrl = flask.url_for('index', _external=True)
    indexParts = list(urlparse.urlparse(indexUrl))

    if ':' not in indexParts[1]:
        indexParts[1] = '{}:{}'.format(socket.gethostname(), app.myPort)
        indexUrl = urlparse.urlunparse(indexParts)

    response = flask.redirect(indexUrl)
    return response


# Leaving this function here for reference for the Authorization Code flow
# Added by Kevin Chan
@app.route('/keycallback')
def keycloakCallback():
    """
    Similar to the oidcCallback function,
    once the authorization provider has cleared the user,
    browser is returned here with a code.
    The code is then checked with the authorization provider
    and if valid a token is returned.

    The token is stored in the session, and the user is assumed to be valid.

    Returns: a token and the redirect url to the new page.
    """
    if app.oidcClient is None:
        raise exceptions.NotImplementedException()

    rspn = dict(req.args.iteritems(multi=True))
    athRp = message.AuthorizationResponse
    oidcCli = app.oidcClient
    aresp = oidcCli.parse_response(athRp, info=rspn, sformat="dict")
    respState = aresp["state"]
    sessState = flask.session.get('state')

    if sessState != respState:
        raise exceptions.NotAuthorizedException()

    args = {
        "code": aresp["code"],
        "redirect_uri": app.oidcClient.redirect_uris[0],
        "client_id": app.oidcClient.client_id,
        "client_secret": app.oidcClient.client_secret,
        "token_endpoint": app.oidcClient.provider_info["token_endpoint"],
        "grant_type": "authorization_code",
    }

    targetUrl = app.oidcClient.provider_info["token_endpoint"]
    tokResp = requests.post(url=targetUrl, data=args)
    tokContent = json.loads(tokResp.content)
    # token = tokContent["access_token"]

    if tokResp.status_code != 200:
        raise exceptions.NotAuthorizedException()
    app.oidcClient.token = tokContent

    # This next line will display the access token on the server front end.
    # If you do not want this uncomment the line above
    flask.session["key"] = app.oidcClient.token["access_token"]
    # change the url depending on where the GA4GH server is hosted
    targetSocket = socket.gethostbyname(socket.gethostname())
    uriStr = 'http://{0}:{1}{2}'
    redirectUri = uriStr.format(targetSocket, app.myPort,
                                flask.session["path"])
    return flask.redirect(redirectUri)


@DisplayedRoute(
    '/datasets/<no(search):id>',
    pathDisplay='/datasets/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getDataset(id):
    return handleFlaskGetRequest(
        id, req, app.backend.runGetDataset)


@DisplayedRoute(
    '/variantannotationsets/<no(search):id>',
    pathDisplay='/variantannotationsets/<id>')
@requires_auth
@oidc.require_login
@requires_token
def getVariantAnnotationSet(id):
    return handleFlaskGetRequest(
        id, req, app.backend.runGetVariantAnnotationSet)


@DisplayedRoute('/phenotypes/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchPhenotypes():
    return handleFlaskPostRequest(
        req, app.backend.runSearchPhenotypes)


@DisplayedRoute('/featurephenotypeassociations/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchGenotypePhenotypes():
    return handleFlaskPostRequest(
        req,
        app.backend.runSearchGenotypePhenotypes)


@DisplayedRoute('/phenotypeassociationsets/search', postMethod=True)
@requires_auth
@oidc.require_login
@requires_token
def searchPhenotypeAssociationSets():
    return handleFlaskPostRequest(
        req, app.backend.runSearchPhenotypeAssociationSets)


# The below methods ensure that JSON is returned for various errors
# instead of the default, html

@app.errorhandler(401)
def unauthorizedHandler(errorString):
    return handleException(exceptions.UnauthorizedException(errorString))


@app.errorhandler(404)
def pathNotFoundHandler(errorString):
    return handleException(exceptions.PathNotFoundException())


@app.errorhandler(405)
def methodNotAllowedHandler(errorString):
    return handleException(exceptions.MethodNotAllowedException())


@app.errorhandler(403)
def notAuthenticatedHandler(errorString):
    return handleException(exceptions.NotAuthenticatedException(errorString))
