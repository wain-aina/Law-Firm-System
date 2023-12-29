// NPM PACKAGES
require("dotenv").config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const session = require("express-session");
const passport = require('passport');
const https = require("https");
const fs = require('fs');
const flash = require('connect-flash');

//These folders have all the logic required to run the program
const passAuth = require('./controllers/passportAuth')
const user = require('./models/user')
const webRoute = require('./routes/webPages')
const login = require('./routes/userLogin')
const forget = require('./routes/forgot')
const reset = require('./routes/resetPass')
const adminLogin = require('./routes/adminLogin')
const adminDash = require('./routes/adminDash')
const invoice = require('./routes/invoiceStuff')
const email = require('./routes/email')
const widgets = require('./routes/widgets')
const reach = require('./routes/reach')
const project = require('./routes/projects')
const caseFiles = require('./routes/caseFiles')
const caseReports = require('./routes/caseReports')
const projectUpdates = require('./routes/projectUpdate')
const deletes = require('./routes/deleteFiles')
const deleteAdmin = require('./routes/adminLogout')
const oneGuy = require('./routes/specificGuy')
const newUpdates = require('./routes/update')
const newContent = require('./controllers/contentAddition')

// PACKAGE INITIALIZATION
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(cookieParser('justiceyoucantrust', {maxAge:60*1000*15}));
app.use(session({secret:"WelcomeToSigani", resave:false, saveUninitialized:false, cookie: {secure: false}}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(function(req, res, next) {
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    res.locals.user = req.user || null;
    next();
});

//These are the route, models, controllers that interact with the whole backend
app.use('/', passAuth);
app.use('/', webRoute);
app.use('/', login);
app.use('/', forget);
app.use('/', reset);
app.use('/', adminLogin);
app.use('/', adminDash);
app.use('/', invoice);
app.use('/', email);
app.use('/', widgets);
app.use('/', reach);
app.use('/', project);
app.use('/', caseFiles);
app.use('/', caseReports);
app.use('/', projectUpdates);
app.use('/', deletes);
app.use('/', deleteAdmin);
app.use('/', oneGuy);
app.use('/', newUpdates);
app.use('/', newContent);

// DATABASE CREATION
mongoose.set('strictQuery', true);
mongoose.connect("mongodb://0.0.0.0:27017/SiganiDB", {useNewUrlParser: true, useUnifiedTopology: true});

// CONFIGURE HTTPS SERVER
const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem', {encoding: 'utf-8'}),
    rejectUnauthorized: true,
};

// HOMEPAGE
app.get("/", (req, res)=>{
    res.render("index", {user:req.user});
});

// THIS IS THE GET ROUTE FOR THE 404 ERROR
// app.use((req, res, next) => {
//    res.status(404).send("Sorry can't find that!")
// });

// SERVER CREATION FOR IT TO RUN
https.createServer(options, app).listen(3000, ()=>{
    console.log("Server started on port 3000");
});

// Remember to implement Argon2 for password encryption which is more superior compared to Bcrypt
