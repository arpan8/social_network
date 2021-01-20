const express = require('express');
const router = express.Router();

const { authLocal, authJwt, loginUser, signout } = require('../../controllers/userController/auth');
const { signup, search, sendfriendreq, acceptrequest } = require('../../controllers/userController/user');

router.post('/user/login', authLocal, loginUser);
router.post('/user/signup', signup)
router.get('/user/signout', authJwt, signout);
router.post('/search/user', authJwt, search);
router.post('/friend/request', authJwt, sendfriendreq);
router.post('/accept/request', authJwt, acceptrequest);


module.exports = router;