var cordova = require('cordova');
var urlutil = require('cordova/urlutil');
var gauth = require('cordova-plugin-googleplus.GAuth');

gauth.init({
    clientId: 'APPLICATION_CLIENT_ID' // CLIENT_ID is populated by the cordova after_prepare hook
})

var GooglePlusProxy = {

    isAvailable: function (success, error) {
        success(gauth !== undefined);
    },

    updateSigninStatus: function (isSignedIn, success, error) {
        if (isSignedIn) {
            var authResponse = gauth.getAuthInstance().authResponse;
            var profile = gauth.getAuthInstance().profile;
            if (success) {
                success({
                    'accessToken': authResponse['access_token'],
                    'expires': authResponse['expires_at'], // not available
                    'expires_in': authResponse['expires_in'],
                    'idToken': authResponse['id_token'],
                    'tokenType': authResponse['token_type'],
                    'serverAuthCode': authResponse['server_auth_code'], // not available
                    'userId': profile['sub'], 
                    'displayName': profile['name'],
                    'familyName': profile['family_name'],
                    'givenName': profile['given_name'],
                    'gender': profile['gender'],
                    'name': profile['name'],
                    'email': profile['email'],
                    'emailVerified': profile['email_verified'],
                    'profile': profile['profile'],
                    'imageUrl': profile['picture']
                });
            }
        }
        else {
            if (error) error({ 'error': 'User not logged in.' });
        }
    },

    trySilentLogin: function (success, error) {
        GooglePlusProxy.updateSigninStatus(gauth.getAuthInstance().isSignedIn.get(), success, error);
    },

    login: function (success, error, options) {
        gauth.getAuthInstance().signIn(options)
            .then(function () {
                GooglePlusProxy.updateSigninStatus(gauth.getAuthInstance().isSignedIn.get(), success, error);
            }, function (err) {
                error(err);
            });
    },

    logout: function (success, error) {
        gapi.auth2.getAuthInstance().signOut();
        success();
    },

    disconnect: function (success, error) {
        gapi.auth2.getAuthInstance().disconnect();
        success();
    },

    getSigningCertificateFingerprint: function (success, error) {
        console.warn('Not implemented.');
        console.trace();
    }
};

module.exports = GooglePlusProxy;
require('cordova/exec/proxy').add('GooglePlus', module.exports);
