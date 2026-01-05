const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    walletId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Wallet',
        required: true,
    },
    referenceNumber: {
        type: String,
        required: true,
        unique: true,
    },
    type: {
        type: String,
        enum: ['credit', 'debit', 'transfer'],
        required: true,
    },
    amount: {
        type: mongoose.Schema.Types.Decimal128,
        required: true,
    },
    currency: { 
        type: String,
        required: true,
        default: 'NGN',
    },
    balanceAfter: {
        type: mongoose.Schema.Types.Decimal128,
        required: true,
    },
    balanceBefore: {
        type: mongoose.Schema.Types.Decimal128,
        required: true,
    },
    description: {
        type: String,
        default: '',
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed'],   
        default: 'pending',
    },
}, { timestamps: true,
    versionKey: false
 });

const Transaction = mongoose.model('Transaction', transactionSchema);

module.exports = Transaction;