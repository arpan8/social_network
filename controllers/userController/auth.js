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
var { proper_date } = require('../../helpers/help');
var today = new Date();
var localOpts = {
    usernameField: 'username',
};

var localStrategy = new LocalStrategy(localOpts, async(username, password, done) => {

    var user = await Users.findOne({
        where: { username: username }
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
            address: req.user.address,
            username: req.user.username,
            cur_company: req.user.cur_company,
            status: req.user.status,
            role: req.user.role,
            role_detail: req.user.role_detail,
            created_by: req.user.created_by,
            modified_by: req.user.modified_by,
            login_date: req.user.login_date
        }
        options = {
            subject: `${userId}`,
            expiresIn: '365d'
        }
        const token = jwt.sign(payload, keys.JWT_SECRET, options);
        return res.status(200).json({
            //"data":req.user,
            "token": token
        })
    }

    return res.status(400).json({ data: req.user })
}

var jwtStrategy = new JwtStrategy(options, async function(jwtPayload, done) {
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

exports.signup = async(req, res) => {
    try {
        var {
            first_name,
            last_name,
            email,
            password,
            mobile_no,
            address,
            username
        } = req.body;
        if (!first_name || !last_name || !email || !password || !mobile_no || !address || !username) {
            return res.status(404).json({
                error: "All fields are required"
            });
        }
        var email_exists = await Users.findOne({
            where: { email: req.body.email }
        });
        if (email_exists) {
            return res.status(404).json({
                error: "Email exists"
            });
        }
        var mobile_exists = await Users.findOne({
            where: { mobile_no: req.body.mobile_no }
        });
        if (mobile_exists) {
            return res.status(404).json({
                error: "Mobile number exists"
            });
        }

        await Users.create({
            first_name: sanitizer.escape(first_name),
            last_name: sanitizer.escape(last_name),
            email: sanitizer.escape(email),
            password: bcrypt.hashSync(password, 10),
            username: sanitizer.escape(username),
            mobile_no: sanitizer.escape(mobile_no),
            address: sanitizer.escape(address),
            cur_company: 2,
            status: "active",
            role: 0,
            role_detail: 'Employee',
            created_by: 0,
            modified_by: 0,
            login_date: proper_date(today)
        });
        res.json({
            success: true,
            message: "User created succesfully"
        });
    } catch (error) {
        console.log(error);
        return res.status(404).json({
            error: "Server problem"
        });
    }
};
exports.signout = async(req, res) => {
    req.logout();
    return res.json({
        message: "Signout successfully"
    })
};