const express = require('express');
const { signup, login, forgetPassword, resetPassword, verifyOtp, resendOtp, getAllUsers } = require('../controller/user.controller');
const isAuth = require('../config/auth');
const router = express.Router();


router.post('/signup', signup);
router.post('/login', login);
router.put('/forget-password', forgetPassword);
router.put('/reset-password', resetPassword);
router.put('/verify-otp', verifyOtp);
router.put('/resend-otp', resendOtp);
router.get('/get-all-users', isAuth, getAllUsers);

module.exports = router;