const User = require("../models/user.models");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sendEmail = require("../config/email");
const { 
  sendWelcomeEmail, 
  sendLoginNotification, 
  sendPasswordResetEmail, 
  sendPasswordResetSuccessEmail 
} = require("../utils/emailService");
const crypto = require("crypto");

const signup = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpiry,
    });

    await newUser.save();

    // // Send OTP email
    // await sendEmail(
    //   email,
    //   "Verify your account",
    //   `Your OTP for account verification is: ${otp}`
    // );

    // Send welcome email (async, don't block response)
    // sendWelcomeEmail({ 
    //   email, 
    //   name,
    //   loginUrl: process.env.LOGIN_URL || 'http://localhost:5000/api/users/login'
    // }).catch(err => console.error('Welcome email failed:', err));

    return res.status(201).json({ message: "User created successfully" });
  } catch (e) {
    console.error("Error during signup:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!user.isVerified) {
      return res
        .status(401)
        .json({ message: "User not verified, please verify your account" });
    }

    const comparePassword = await bcrypt.compare(password, user.password);
    if (!comparePassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = await jwt.sign({ userId: user._id, name: user.name }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Send login notification email (async, don't block response)
    // sendLoginNotification({
    //   email: user.email,
    //   name: user.name,
    //   location: req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Unknown',
    //   device: req.headers['user-agent'] || 'Web Browser',
    //   resetPasswordUrl: process.env.FORGOT_PASSWORD_URL || 'http://localhost:5000/api/users/forgot-password'
    // }).catch(err => console.error('Login notification failed:', err));

    return res.status(200).json({ message: "Login successful", token });
  } catch (e) {
    console.error("Error during login:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const forgetPassword = async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    
    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    
    // Also generate OTP for backward compatibility
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    await user.save();

    // // Send old OTP email
    // await sendEmail(
    //   email,
    //   "Password Reset OTP",
    //   `Your OTP for password reset is: ${otp}`
    // );

    // // Send new formatted password reset email with token
    // const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
    // sendPasswordResetEmail({
    //   email: user.email,
    //   name: user.name,
    //   resetToken,
    //   resetUrl,
    //   expiryTime: '1 hour'
    // }).catch(err => console.error('Password reset email failed:', err));

    return res.status(200).json({ message: "Password reset instructions sent to email", otp });
  } catch (e) {
    console.error("Error during forget password:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const resetPassword = async (req, res) => {
  const { otp, newPassword, token } = req.body;
  try {
    if ((!otp && !token) || !newPassword) {
      return res.status(400).json({ message: "Reset token/OTP and new password are required" });
    }
    
    let user;
    
    // Support both token and OTP methods
    if (token) {
      const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
      user = await User.findOne({
        resetPasswordToken: hashedToken,
        resetPasswordExpires: { $gt: Date.now() }
      });
      
      if (!user) {
        return res.status(400).json({ message: "Invalid or expired reset token" });
      }
    } else {
      user = await User.findOne({ otp });
      if (!user) {
        return res.status(404).json({ message: "Invalid OTP" });
      }
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = null;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;
    await user.save();
    
    // Send password reset success email
    // sendPasswordResetSuccessEmail({
    //   email: user.email,
    //   name: user.name,
    //   location: req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'Unknown',
    //   loginUrl: process.env.LOGIN_URL || 'http://localhost:5000/api/users/login'
    // }).catch(err => console.error('Password reset success email failed:', err));
    
    return res.status(200).json({ message: "Password reset successful" });
  } catch (e) {
    console.error("Error during reset password:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const verifyOtp = async (req, res) => {
  const { otp } = req.body;
  try {
    if (!otp) {
      return res.status(400).json({ message: "OTP is required" });
    }

    const user = await User.findOne({ otp });
    if (!user) {
      return res.status(404).json({ message: "Invalid OTP" });
    }
    if (user.otpExpiry < new Date()) {
      return res.status(400).json({ message: "OTP has expired" });
    }

    user.isVerified = true;
    user.otp = null;
    user.otpExpiry = null;
    await user.save();
    return res.status(200).json({ message: "User verified successfully" });
  } catch (e) {
    console.error("Error during OTP verification:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const resendOtp = async (req, res) => {
  const { email } = req.body;
  try {
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes
    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();
    return res.status(200).json({ message: "OTP resent successfully", otp });
  } catch (e) {
    console.error("Error during resending OTP:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const getAllUsers = async (req, res) => {
   const { userId } = req.user;
  try {
    const adminUser = await User.findById(userId);
    if (adminUser.role !== 'admin') {
      return res.status(403).json({ message: "Access denied" });
    }
    const users = await User.find().select('-password -otp -otpExpiry');
    return res.status(200).json(users);
  } catch (e) {
    console.error("Error fetching users:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

module.exports = { signup, login, forgetPassword, resetPassword, verifyOtp, resendOtp, getAllUsers };