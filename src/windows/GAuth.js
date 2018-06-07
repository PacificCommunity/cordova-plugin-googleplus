// ns
var Http = Windows.Web.Http;
var Cryptography = Windows.Security.Cryptography;
var Uri = Windows.Foundation.Uri;

var defaults = {
    clientId: 'CLIENT_ID',
    redirectUri: Windows.ApplicationModel.Package.current.id.name + ':/oauth2redirect',
    scope: 'openid profile email'
}

var authorizationEndpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
var tokenEndpoint = 'https://www.googleapis.com/oauth2/v4/token';
var userInfoEndpoint = 'https://www.googleapis.com/oauth2/v3/userinfo';

var sha = Cryptography.Core.HashAlgorithmProvider.openAlgorithm(Cryptography.Core.HashAlgorithmNames.sha256);


/**
 * Sigleton used to configure and access auth instance
 */

function GAuth() {
    this._authInstance = null;
    this._restClient = new RestClient();
}

GAuth.prototype.init = function (options) {
    if (!options) options = {};
    this._restClient.init(options);
}

GAuth.prototype.getAuthInstance = function () {
    if (!this._authInstance) {
        this._authInstance = new AuthInstance(this._restClient);
    }
    return this._authInstance;
}

/**
 * provide access to Google Oauth REST API
 */

function RestClient() {
    this.init();
}

RestClient.prototype.initHttpClient = function () {
    this.httpClient = new Http.HttpClient();
}

RestClient.prototype.init = function (options) {
    if (!options) options = {};
    this.clientId = options.clientId || this.clientId || defaults.clientId;
    this.redirectUri = options.redirectUri || this.redirectUri || defaults.redirectUri;
    this.scope = options.scope || this.scope || defaults.scope;
    if(!this.httpClient) {
        this.initHttpClient();
    } 
}

RestClient.prototype.reset = function () {
    this.initHttpClient();
}

RestClient.prototype.authorizeAsync = function (challenge, options) {
    options = options || {};
    var scope = options.scope || this.scope;
    var clientId = options.clientId || this.clientId;
    var redirectUri = options.redirectUri || this.redirectUri;

    var authorizationRequest = authorizationEndpoint +
        '?response_type=code' +
        '&scope=' + encodeURIComponent(scope) +
        '&redirect_uri=' + encodeURIComponent(redirectUri) +
        '&client_id=' + clientId +
        '&state=' + challenge.state +
        '&code_challenge=' + challenge.codeChallenge +
        '&code_challenge_method=' + challenge.codeChallengeMethod;

    authURI = new Uri(authorizationRequest);
    endURI = new Uri(this.redirectUri);

    // test code
    // return Windows.System.Launcher.launchUriAsync(authURI);

    var task = Windows.Security.Authentication.Web.WebAuthenticationBroker.authenticateAsync(
        Windows.Security.Authentication.Web.WebAuthenticationOptions.None,
        authURI,
        endURI);

    return task.then(function (webAuthenticationResult) {
        switch (webAuthenticationResult.responseStatus) {
            case Windows.Security.Authentication.Web.WebAuthenticationStatus.success:
                var result = getCallbackParams(webAuthenticationResult.responseData);
                if (result.error) {
                    throw ('OAuth authorization error: ' + result.error);
                }
                if (!result.code || !result.state) {
                    throw ('Malformed authorization response.');
                }
                if (result.state !== challenge.state) {
                    throw ('Received request with invalid state: ' + state);
                }

                return result;
            case Windows.Security.Authentication.Web.WebAuthenticationStatus.errorHttp:
                throw webAuthenticationResult.responseErrorDetail;
            default:
                throw webAuthenticationResult.responseErrorDetail;
        }
    }, function (err) {
        throw err;
    });
}

RestClient.prototype.performCodeExchangeAsync = function (code, codeVerifier) {
    var tokenRequestBody = 'code=' + code +
        '&redirect_uri=' + encodeURIComponent(this.redirectUri) +
        '&client_id=' + this.clientId +
        '&code_verifier=' + codeVerifier +
        '&scope=' +
        '&grant_type=authorization_code';

    var uri = new Uri(tokenEndpoint);
    var content = new Http.HttpStringContent(tokenRequestBody, Windows.Storage.Streams.UnicodeEncoding.utf8, 'application/x-www-form-urlencoded');

    return this.httpClient.postAsync(uri, content)
        .then(function success(response) {
            if (!response.isSuccessStatusCode) {
                throw 'Authorization code exchange failed.';
            }

            return response.content.readAsStringAsync();
        }).then(function (responseString) {
            return parseTokens(responseString);
        });
}

RestClient.prototype.refreshTokenAsync = function (refreshToken) {
    if (!refreshToken) {
        throw 'Please provide a refresh token.';
    }
    var tokenRefreshBody = 'refresh_token=' + refreshToken +
        '&redirect_uri=' + encodeURIComponent(this.redirectUri) +
        '&client_id=' + this.clientId +
        '&grant_type=refresh_token';

    var uri = new Uri(tokenEndpoint);
    var content = new Http.HttpStringContent(tokenRefreshBody, Windows.Storage.Streams.UnicodeEncoding.utf8, 'application/x-www-form-urlencoded');

    return this.httpClient.postAsync(uri, content)
        .then(function success(response) {
            if (!response.isSuccessStatusCode) {
                throw 'Authorization code refresh failed.';
            }

            return response.content.readAsStringAsync();
        }).then(function (responseString) {
            return parseTokens(responseString);
        });
}

RestClient.prototype.getBasicProfileAsync = function () {
    var userInfoUri = new Uri(userInfoEndpoint);
    return this.httpClient.getAsync(userInfoUri)
        .then(function (userinfoResponse) {
            return userinfoResponse.content.readAsStringAsync();
        }).then(function (userinfoResponseContent) {
            return JSON.parse(userinfoResponseContent);
        });
}

RestClient.prototype.addBearerHeader = function (accessToken) {
    this.httpClient.defaultRequestHeaders.authorization = new Http.Headers.HttpCredentialsHeaderValue('Bearer', accessToken);
}

/**
 * Manage auth process.
 * Try to follow gapi.js methods.
 */

function AuthInstance(restClient) {
    var self = this;
    this.restClient = restClient;
    self._signedIn = false;
    this.isSignedIn = {
        get: function () {
            return self._signedIn;
        }
    }

    this.init();
}

AuthInstance.prototype.init = function () {
    this._signedIn = false;
    this.getAuthResponse = null;
    this.profile = null;

    this.accessToken = null;
    this.refreshToken = null;
    this.restClient.reset();
}

AuthInstance.prototype.signIn = function (options) {
    var self = this;
    var challenge = createCodeChallenge();

    return this.restClient.authorizeAsync(challenge, options)
        .then(function (authResponse) {
            return self.restClient.performCodeExchangeAsync(authResponse.code, challenge.codeVerifier);
        }).then(function (tokenResponse) {
            self.authResponse = tokenResponse;
            self.accessToken = tokenResponse.access_token;
            self.refreshToken = tokenResponse.refresh_token;
            self.restClient.addBearerHeader(self.accessToken);
            return self.restClient.getBasicProfileAsync();
        }).then(function (profileResponse) {
            self.profile = profileResponse;
            self._signedIn = true;
            return profileResponse;
        });
}

AuthInstance.prototype.signOut = function () {
    this.init();
}

AuthInstance.prototype.disconnect = function () {
    this.init();
}

function parseTokens(responseString) {
    var tokens = JSON.parse(responseString);
    return tokens;
}

function getCallbackParams(uri) {
    var authorizationResponse = new Uri(uri);
    var queryString = authorizationResponse.query;

    var queryStringParams = queryString
        .substring(1)
        .split('&')
        .reduce(function (obj, c) {
            var entry = c.split('=');
            obj[entry[0]] = decodeURIComponent(entry[1]);
            return obj;
        }, {});

    return queryStringParams;
}

function createCodeChallenge() {
    // Generates state and PKCE values.
    var state = randomDataBase64url(32);
    var codeVerifier = randomDataBase64url(32);
    var codeChallenge = base64urlencodeNoPadding(sha256(codeVerifier));

    return {
        state: state,
        codeVerifier: codeVerifier,
        codeChallenge: codeChallenge,
        codeChallengeMethod: 'S256'
    }
}

function randomDataBase64url(length) {
    var buffer = Cryptography.CryptographicBuffer.generateRandom(length);
    return base64urlencodeNoPadding(buffer);
}

function base64urlencodeNoPadding(buffer) {
    var base64 = Cryptography.CryptographicBuffer.encodeToBase64String(buffer);

    // Converts base64 to base64url.
    base64 = base64.replace(/\+/g, '-');
    base64 = base64.replace(/\//g, '_');
    // Strips padding.
    base64 = base64.replace(/=/g, '');

    return base64;
}

function sha256(inputString) {
    var buff = Cryptography.CryptographicBuffer.convertStringToBinary(inputString, Cryptography.BinaryStringEncoding.utf8);
    return sha.hashData(buff);
}

module.exports = new GAuth();
