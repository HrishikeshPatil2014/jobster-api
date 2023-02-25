const express = require('express')
const router = express.Router()
const authenticateUser = require('../middleware/authentication')
const { register, login, updateUser } = require('../controllers/auth')
const testUser = require('../middleware/testUser');

const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    message: {
        msg: 'Too many requests from this IP, please try again after 15 mins',
    },
});

router.post('/register', apiLimiter, register);
router.post('/login', apiLimiter, login);
router.patch('/updateuser', authenticateUser, testUser, updateUser);

module.exports = router
