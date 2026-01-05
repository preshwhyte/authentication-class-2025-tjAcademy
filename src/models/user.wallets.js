const mongoose = require('mongoose');

const walletSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,   
        ref: 'User',
        required: true,
    },
    balance: {
        type: mongoose.Schema.Types.Decimal128,
        default: 0,
    },
    currency: {
        type: String,   
        required: true,
        default: 'NGN',
    },
    accountNumber: {
        type: String,
        required: true,
        unique: true,
    },
}, { timestamps: true,
    versionKey: false
 });

const Wallet = mongoose.model('Wallet', walletSchema);

module.exports = Wallet;