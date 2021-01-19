const express = require('express');
const router = express.Router();

router.use('/api', require('./userRoutes/user'));

module.exports = router;