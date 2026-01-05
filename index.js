const express = require('express');
const app = express();
const morgan = require('morgan');
const connectDB = require('./src/config/db');
require('dotenv').config();

const userRoutes = require('./src/routes/user.routes');
const walletRoutes = require('./src/routes/user.wallets.routes');

const port = process.env.PORT || 5000;



app.use(express.json());
app.use(morgan('dev'));

connectDB();

app.get('/', (req, res) => {
    res.send('Welcome To My Auth Class');
});


app.use('/api/users', userRoutes);
app.use('/api/wallets', walletRoutes);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});