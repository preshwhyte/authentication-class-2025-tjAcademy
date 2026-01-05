const routes = require('express').Router();
const { createWallet, getAllWallets } = require('../controller/user.wallets');
const isAuth = require('../config/auth');
const router = require('./user.routes');

routes.post('/create-wallet', isAuth, createWallet);
routes.get('/get-all-wallets', isAuth, getAllWallets);

module.exports = routes;