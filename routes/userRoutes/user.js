const express = require('express');
const router = express.Router();

const { authLocal, authJwt, loginUser, signup, signout, isAdmin } = require('../../controllers/userController/auth');

router.post('/user/login', authLocal, loginUser);
router.get('user/signout', authJwt, signout);

module.exports = router;