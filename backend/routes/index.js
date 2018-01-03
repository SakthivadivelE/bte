var express = require('express');
var router = express.Router();
let verifytoken = require('../middleware/verifytoken');
let user = require('./user');
router.use('/',user);

module.exports = router;