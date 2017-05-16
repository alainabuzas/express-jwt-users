var express = require('express');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
var app = express();
var expressJWT = require('express-jwt');
var User = require('./models/user');
var jwt = require('jsonwebtoken');

var secret = "mysupersecretpassword";

mongoose.connect('mongodb://localhost:27017/myauthenticatedusers');

app.use(bodyParser.urlencoded({ extended: true }));
app.use('/api/users', expressJWT({ secret: secret }).unless({ method: 'POST' }));
app.use(function(err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
        res.status(401).send({ message: 'You need an auth token to view this info' })
    }
})
app.use('/api/users', require('./controllers/users'));

app.get('/', function(req, res) {
    res.sendFile(__dirname + '/views/index.html');
});

app.post('/api/auth', function(req, res) {
    // some code to check that a user's credentials are right #bcryptmaybe?
    // collect any information we want to include in the token, like that user's info
    User.findOne({ email: req.body.email }, function(err, user) {
        if (err || !user) return res.send({ message: 'User not found' });
        user.authenticated(req.body.password, function(err, result) {
            if (err || !result) return res.send({ message: 'User not authenticated' });
            // make a token already & send it as JSON

            var token = jwt.sign(JSON.stringify(user), secret);
            res.send(token);
        });
    });
});

app.listen(3000);
