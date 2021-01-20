const express = require("express");
const app = express();
const dotenv = require("dotenv");
dotenv.config();
const port = process.env.PORT || 3000;
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
const path = require("path");
var passport = require("passport");
const cors = require("cors");
const multer = require("multer");
var compression = require("compression");
const helmet = require("helmet");
const server = require('http').Server(app);
const io = require('socket.io')(server);
require('./socket/streams')(io)

//middlewares

app.use(helmet());
app.use(compression());
app.use(morgan("dev"));
//app.use(bodyParser.urlencoded( {extended: false}));
//app.use(bodyParser.urlencoded({limit: '50mb', extended: true, parameterLimit:50000}));
app.use(bodyParser.json({ limit: "50mb", extended: true, parameterLimit: 50000 }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use(cors());

//routes middlewares
app.use(require("./routes"));

//passport
app.use(passport.initialize());
app.use(passport.session());

//cors
const allowCrossDomain = function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

    // intercept OPTIONS method
    if ("OPTIONS" == req.method) {
        res.sendStatus(200);
    } else {
        next();
    }
};
app.use(allowCrossDomain);

server.listen(port, () => {
    console.log(`Server is running on ${port}`);
});