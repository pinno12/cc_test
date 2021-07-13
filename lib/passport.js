var db2 = require('../lib/db2');
var bcrypt = require('bcrypt');

module.exports = function (app) {

    var passport = require('passport'),
        LocalStrategy = require('passport-local').Strategy;

    app.use(passport.initialize());
    app.use(passport.session());

    passport.serializeUser(function (user, done) {
        console.log('serializeUser', user);
        done(null, user.id);
    });

    passport.deserializeUser(function (id, done) {
        var user = db2.get('users').find({
            id: id
        }).value();
        console.log('deserializeUser', id, user);
        done(null, user);
    });

    passport.use(new LocalStrategy({
            usernameField: 'phone',
            passwordField: 'pwd'
        },
        function (phone, password, done) {
            console.log('LocalStrategy', phone, password);
            var user = db2.get('users').find({
                phone: phone
            }).value();
            if (user) {
                bcrypt.compare(password, user.password, function(err,result){
                    if(result){
                        return done(null, user, {
                            message: 'Welcome.'
                        });
                    } else {
                        return done(null, false, {
                            message: 'Password is not correct.'
                        });
                    }
                });
            } else {
                return done(null, false, {
                    message: 'There is no phone.'
                });
            }
        }
    ));
    return passport;
}