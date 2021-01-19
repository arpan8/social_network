"use strict";

var express = require("express");

var app = express();

var dotenv = require("dotenv");

dotenv.config();
var port = process.env.PORT || 3000;

var bodyParser = require("body-parser");

var cookieParser = require("cookie-parser");

var morgan = require("morgan");

var path = require("path");

var passport = require("passport");

var cors = require("cors");

var multer = require("multer");

var compression = require("compression");

var helmet = require("helmet"); //console.log(process.env.PORT)
//middlewares


app.use(helmet());
app.use(compression());
app.use(morgan("dev")); //app.use(bodyParser.urlencoded( {extended: false}));
//app.use(bodyParser.urlencoded({limit: '50mb', extended: true, parameterLimit:50000}));

app.use(bodyParser.json({
  limit: "50mb",
  extended: true,
  parameterLimit: 50000
}));
app.use(cookieParser());
app.use(express["static"](path.join(__dirname, "public")));
app.use(cors()); //routes middlewares

app.use(require("./routes")); //passport

app.use(passport.initialize());
app.use(passport.session()); //cors

var allowCrossDomain = function allowCrossDomain(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization"); // intercept OPTIONS method

  if ("OPTIONS" == req.method) {
    res.sendStatus(200);
  } else {
    next();
  }
};

app.use(allowCrossDomain);
app.listen(port, function () {
  console.log("Server is running on ".concat(port));
});