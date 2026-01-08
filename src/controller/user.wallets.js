const UserWallet = require("../models/user.wallets");
const User = require("../models/user.models");
const sendEmail = require("../config/email");

// Create Wallet
const createWallet = async (req, res) => {
  try {
    const { userId } = req.user;
    const { phoneNumber, currency } = req.body;
    if (!userId) {
      return res.status(400).json({ message: "User ID is required" });
    }

    const existingUser = await User.findById(userId);
    if (!existingUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Remove +234 or leading 0 from phone number
    const normalizedPhone = phoneNumber.replace(/^(\+234|0)/, "");

    existingUser.phoneNumber = phoneNumber;
    await existingUser.save();

    const newWallet = new UserWallet({
      userId: userId,
      balance: 0,
      currency: currency,
      accountNumber: normalizedPhone,
    });

    await newWallet.save();
    return res
      .status(201)
      .json({ message: "Wallet created successfully", wallet: newWallet });
  } catch (e) {
    console.error("Error creating wallet:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// Get All User Wallets
const getAllWallets = async (req, res) => {
  try {
    const { userId } = req.user;
    if (!userId) {
      return res.status(400).json({ message: "User ID is required" });
    }

    const wallets = await UserWallet.find().populate(
      "userId",
      "email"
    );
    return res.status(200).json({ wallets });
  } catch (e) {
    console.error("Error fetching wallets:", e);
    return res.status(500).json({ message: "Internal server error" });
  }
};

module.exports = {
  createWallet,
  getAllWallets,
};
