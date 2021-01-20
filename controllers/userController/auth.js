const Users = require("../../models/index").user
const bcrypt = require('bcrypt');
var passport = require('passport');
const jwt = require('jsonwebtoken');
var LocalStrategy = require('passport-local');
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var options = {};
options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
options.secretOrKey = process.env.JWT_SECRET;
//const errorHandler = require('../validators/index'); 

var localOpts = {
    usernameField: 'email',
};

var localStrategy = new LocalStrategy(localOpts, async (email, password, done) => {

    var user = await Users.findOne({
        where: { email: email }
    });

    var isValidPassword = (userpass, password) => {
        return bcrypt.compareSync(password, userpass);
    }

    //console.log(user);
    if (!user || !isValidPassword(user.password, password)) {
        return done(null, 'Username or password do not match')
    }
    return done(null, user)
});
passport.use(localStrategy);

exports.authLocal = passport.authenticate('local', {
    session: false
});

exports.loginUser = (req, res) => {
    var userId = req.user.id
    //console.log(req.user.id);
    if (userId) {
        const payload = {
            id: req.user.id,
            first_name: req.user.first_name,
            last_name: req.user.lastname,
            email: req.user.email,
            //password: req.user.password,
            mobile_no: req.user.mobile_no,
            //username: req.user.username
        }
        options = {
            subject: `${userId}`,
            expiresIn: '365d'
        }
        const token = jwt.sign(payload, process.env.JWT_SECRET, options);
        return res.status(200).json({
            //"data":req.user,
            "token": token
        })
    }

    return res.status(400).json({ data: req.user })
}

var jwtStrategy = new JwtStrategy(options, async function (jwtPayload, done) {
    //console.log(jwtPayload);   
    var user = await Users.findByPk(jwtPayload.sub);
    //console.log(user);
    if (!user) {
        return done(null, "User Access denied");
    } else {
        return done(null, jwtPayload);
    }

})
passport.use(jwtStrategy);

exports.authJwt = passport.authenticate('jwt', { session: false });

exports.isAdmin = (req, res, next) => {
    //console.log(req.user);
    if (req.user.role === 0) {
        return res.status(403).json({
            error: 'Admin resourse! Access denied'
        });
    }
    next();
};

exports.signout = async (req, res) => {
    req.logout();
    return res.json({
        message: "Signout successfully"
    })
};