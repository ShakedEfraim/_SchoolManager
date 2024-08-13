// -- IMPORTS --
const express = require('express');
const bodyParser = require('body-parser');

// -- CONTROLLER IMPORTS --
const authController = require('./controllers/auth');
const authenticateJWT = require('./middlewares/auth');
const ensureDefaults = require('./middlewares/ensureDefaults');
const renderWithLayout = require('./middlewares/renderWithLayout');
const cookieParser = require('cookie-parser');

// -- DB & CONFIG IMPORTS --
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
const port = 3000;


// -- EJS TEMPLATING ENGINE --
app.set('view engine', 'ejs'); // Use Template Engine for EJS

// -- REQUEST MIDDLEWARES --
app.use(express.static('public')); // Define a public static folder
app.use(bodyParser.urlencoded({ extended: true })); // Define a body parser for Forms

// -- RESPONSE MIDDLEWARES --
//app.use(resLogger); // Use ResponseLogger Middleware
app.use(ensureDefaults);
app.use(renderWithLayout('_layout'));
app.use(cookieParser(process.env.COOCKIE_SECRET));

// -- DATA / DB / CONFIG --
// -- USE MONGODB --
// 1. Create connection string
const connectionString = process.env.MONGODB_URI;
mongoose.connect(connectionString) // 2. Connect to MongoDB
    .then(() => {
        console.log("MongoDB Connected Successfully!");
    })
    .catch(err => {
        console.log(`MongoDB Failed to Connect: ${err.message}`);
    });

// -- CONTROLLER -- MVC
app.get('/', (req, res) => res.redirect('auth/login'));

app.use('/auth', authController);


app.listen(port, () => {
    console.log(`Banking app listening at http://localhost:${port}`);
});