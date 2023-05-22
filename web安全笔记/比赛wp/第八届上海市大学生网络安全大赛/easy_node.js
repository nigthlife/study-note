

const express = require('express');
const app = express();
var bodyParser = require('body-parser')
app.use(bodyParser.json())
const { VM } = require("vm2");
const fs = require("fs");
const session = require("express-session");
const cookieParser = require('cookie-parser');
session_secret = Math.random().toString(36).substr(2);
app.use(cookieParser(session_secret));
app.use(session({ secret: session_secret, resave: true, saveUninitialized: true }))

function copyArray(arr1) {
    var arr2 = new Array(arr1.length);
    for (var i = 0; i < arr1.length; i++) {
        if (arr1[i] instanceof Object) {
            arr2[i] = copyArray(arr1[i])
        } else {
            arr2[i] = arr1[i]
        }
    }
    return arr2
}

{
    "name": "admin",
        "__proto__": {
        "properties": [
            "name",
            "debugger"
        ]
    }

}

app.post('/vm2_tester', function (req, res) {
    if (req.body.name) {
        req.session.user = { "username": req.body.name }
        const properties = req.body.properties
        for (let i = 0; i < properties.length; i++) {
            if (properties[i] == 'vm2_tester') {
                res.send('cant set vm2_tester by self')
                return
            }
        }
        req.session.user.properties = copyArray(properties)
        res.send('Success')
    } else {
        res.send("input username")
    }
})

app.get('/', function (req, res) {
    res.send('see `/src`');
});


app.post('/vm2', function (req, res) {

    if (req.session.user && req.session.user.properties) {
        for (var i = 0; i < req.session.user.properties.length; i++)
            if (req.session.user.properties[i] == 'vm2_tester') {
                if (req.body["code"]) {
                    if (/\b(?:function)\b/.test(req.body["code"])) {
                        res.send("define function not allowed")
                        return;
                    }
                    if (/\b(?:getPrototypeOf)\b/.test(req.body["code"])) {
                        res.send("define getPrototypeOf not allowed")
                        return;
                    }
                    const vm = new VM();
                    res.send(vm.run(req.body["code"]))
                    return
                } else {
                    res.send("input code")
                }
            }
    } else {
        res.send("not vm2 tester rights")
    }

})


app.get('/', function (req, res) {
    res.send('see `/src`,use vm2 3.9.16');
});
app.get('/src', function (req, res) {
    var data = fs.readFileSync('app.js');
    res.send(data.toString());
});

app.listen(3000, function () {
    console.log('start listening on port 3000');
});
