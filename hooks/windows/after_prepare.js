#!/usr/bin/env node
'use strict';

var fs = require('fs');

var getPreferenceValue = function(config, name) {
    var value = config.match(new RegExp('name="' + name + '" value="(.*?)"', "i"));
    if(value && value[1]) {
        return value[1]
    } else {
        return null
    }
};

var APPLICATION_CLIENT_ID = '';

if(process.argv.join("|").indexOf("APPLICATION_CLIENT_ID=") > -1) {
    APPLICATION_CLIENT_ID = process.argv.join("|").match(/APPLICATION_CLIENT_ID=(.*?)(\||$)/)[1]
} else {
    var config = fs.readFileSync("config.xml").toString();
    APPLICATION_CLIENT_ID = getPreferenceValue(config, "APPLICATION_CLIENT_ID");
}

var files = [
    "platforms/windows/www/plugins/cordova-plugin-googleplus/src/windows/GAuth.js",
    "platforms/windows/www/plugins/cordova-plugin-googleplus/src/windows/GooglePlusProxy.js",
    "platforms/windows/platform_www/plugins/cordova-plugin-googleplus/src/windows/GooglePlusProxy.js"
];

for(var i=0; i<files.length; i++) {
    try {
        var contents = fs.readFileSync(files[i]).toString();
        fs.writeFileSync(files[i], contents.replace(/APPLICATION_CLIENT_ID/g, APPLICATION_CLIENT_ID));
    } catch(err) {}
}
