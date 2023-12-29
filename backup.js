// NPM PACKAGES

require("dotenv").config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const session = require("express-session");
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const bcrypt = require('bcrypt');
const async = require("async");
const crypto = require('crypto');
const nodemailer = require("nodemailer");
const https = require("https");
const fs = require('fs');
const flash = require('connect-flash');
const requests = require('requests');
const await = require('await');
const methodOverride = require("method-override");
const multer = require('multer');
const path = require('path');

const app = express();

const saltRounds = 8;

// PACKAGE INITIALIZATION

app.set('view engine', 'ejs');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname + '/uploads')));
app.use(cookieParser('justiceyoucantrust', {maxAge:60*1000*15}));
app.use(session({secret:"WelcomeToSigani", resave:false, saveUninitialized:false}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method", {methods:["GET", "POST"]}))
app.use(flash());

app.use(function(req, res, next) {
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    res.locals.user = req.user || null;
    next();
})


// DATABASE CREATION

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://0.0.0.0:27017/SiganiDB", {useNewUrlParser: true, useUnifiedTopology: true});

let image_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/images')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let invoice_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/invoices')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let project_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/projects')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let report_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/reports')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let gov_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/gov')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let fahm_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/family')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let court_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/court')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let userProject_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/userProjects')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let email_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/emails')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let client_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/clientFiles')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let orgFiles_storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/orgFiles')
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname)
    }
})

let email_upload = multer({ storage: email_storage }).array('attachment', 100);
let client_upload = multer({storage:client_storage}).array('document', 100);
let image_upload = multer({ storage: image_storage }).array('myFile', 100);
let invoice_upload = multer({ storage: invoice_storage }).array('myFile', 100);
let project_upload = multer({ storage: project_storage }).array('myFile', 100);
let report_upload = multer({ storage: report_storage }).array('myFile', 100);
let gov_upload = multer({ storage: gov_storage }).array('myFile', 100);
let fahm_upload = multer({ storage: fahm_storage }).array('myFile', 100);
let court_upload = multer({ storage: court_storage }).array('myFile', 100);
let userProject_upload = multer({ storage: userProject_storage }).array('myReport', 100);
let orgFiles_upload = multer({storage: orgFiles_storage}).array('orgFiles', 100);

// NODEMAILER CONFIGURATION

const transporter = nodemailer.createTransport({
    service:'gmail',
    host: 'smtp.gmail.com',
    secure: true,
    auth: {
        user: process.env.AUTH_EMAIL,
        pass: process.env.AUTH_APP_PASS
    },
});

// CONFIGURE HTTPS SERVER

const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem', {encoding: 'utf-8'}),
    rejectUnauthorized: true,
};

// MONGOOSE USER SCHEMAS

const validateEmail = email => {
    const re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    return re.test(email)
};

const userSchema = new mongoose.Schema({
    twitterId:String,
    googleId:String,
    email: String,
    password: {type:String},
    username: {
        type: String,
        sparse: true,
        trim: true,
        lowercase: true,
        unique: false,
        require: true,
        validate: [validateEmail, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    isAdmin: {type:Boolean, default:false},
    clientType: String,
    occupation: String,
    phoneNumber: String,
    idNumber: Number,
    passportNumber: String,
    postalAddress: String,
    physicalAddress: String,
    kraPin: String,
    profilePhoto:{filename:String, path:String, originalName:String},
    files:[{
        filename: String,
        path: String,
        originalName: String
    }]
});

const adminSchema = new mongoose.Schema({
    username: String,
    isAdmin: {type:Boolean, default:false},
    role: {
        type: String,
        enum: ['employee', 'admin'],
        default: 'employee'
    },
    password: {type:String},
});

const consultationSchema = new mongoose.Schema({
    name: String,
    phone:  Number,
    mailAddress: {
        type: String,
        sparse: true,
        trim: true,
        lowercase: true,
        unique: false,
        require: true,
        validate: [validateEmail, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    date: Date,
    time: String,
    area: String,
    purpose: String,
    files:[{
        filename: String,
        path: String,
        originalName: String
    }]
});

const caseSchema = new mongoose.Schema({
    caseTitle: String,
    caseType: String,
    clientEmail: String,
    orgName:String,
    lawyer1: String, lawyer2: String, lawyer3: String, lawyer4: String,
    lawyer5: String, lawyer6: String, lawyer7: String, lawyer8: String,
    job1: String, job2: String, job3: String, job4: String,
    job5: String, job6: String, job7: String, job8: String,
    job1: String,
    job1Completed: {type:Boolean,default:false},
    job2: String,
    job2Completed: {type:Boolean,default:false},
    job3: String,
    job3Completed: {type:Boolean,default:false},
    job4: String,
    job4Completed: {type:Boolean,default:false},
    job5: String,
    job5Completed: {type:Boolean,default:false},
    job6: String,
    job6Completed: {type:Boolean,default:false},
    job7: String,
    job7Completed: {type:Boolean,default:false},
    job8: String,
    job8Completed: {type:Boolean,default:false},
    lawyerNumber: Number,
});

const memberSchema = new mongoose.Schema({
    full_name: String,
    mail_name:  {
        type: String,
        sparse: true,
        trim: true,
        lowercase: true,
        unique: false,
        require: true,
        validate: [validateEmail, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    occupation: String,
    user_phone: Number,
    user_bio: String,
    job_bio: String,
    user_fun1: String,
    user_fun2: String,
    user_fun3: String,
});

const eventSchema = new mongoose.Schema({
    eventType: String,
    eventDate: Date,
    eventTime: String,
});

const agendaSchema = new mongoose.Schema({
    aName: String,
    aPriority: String,
    aTime: String,
    expireAt: {type: Date, expires: 43200}

});

const reportSchema = new mongoose.Schema({
    cnum: Number,
    cintro: String,
    cbio: String,
    cname: String,
    cphone: Number,
    cmail: {
        type: String,
        sparse: true,
        trim: true,
        lowercase: true,
        unique: false,
        require: true,
        validate: [validateEmail, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    cStatus: String,
});

const projectSchema = new mongoose.Schema({
    ctitle: String,
    mem1: String,
    mem2: String,
    mem3: String,
    mem4: String,
    mem5: String,
    mem6: String,
    mem7: String,
    mem8: String,
    task1: String,
    task1Completed: {type:Boolean,default:false},
    task2: String,
    task2Completed: {type:Boolean,default:false},
    task3: String,
    task3Completed: {type:Boolean,default:false},
    task4: String,
    task4Completed: {type:Boolean,default:false},
    task5: String,
    task5Completed: {type:Boolean,default:false},
    task6: String,
    task6Completed: {type:Boolean,default:false},
    task7: String,
    task7Completed: {type:Boolean,default:false},
    task8: String,
    task8Completed: {type:Boolean,default:false},
    files:[{
        filename: String,
        path: String,
        originalName: String
    }]
});

const updateSchema = new mongoose.Schema({
    uName: String,
    uNews: String,
});

const invoiceSchema = new mongoose.Schema({
    cname: String, cEmail:{type: String, sparse: true, trim: true, lowercase: true, unique: false, require: true,
        validate: [validateEmail, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    }, clocale:String, cid: String, cissue: String,cphone:Number,
    serv1:String, quan1: String, unit1: Number,
    serv2:String, quan2: String, unit2: Number,
    serv3:String, quan3: String, unit3: Number,
    serv4:String, quan4: String, unit4: Number,
    serv5:String, quan5: String, unit5: Number,
    serv6:String, quan6: String, unit6: Number,
    serv7:String, quan7: String, unit7: Number,
    serv8:String, quan8: String, unit8: Number,
    serv9:String, quan9: String, unit9: Number,
    serv10:String, quan10: String, unit10: Number,
    serv11:String, quan11: String, unit11: Number,
    ctax:Number,
});

const fileSchema = new mongoose.Schema({
    filename: String,
    path: String,
    originalName: String
});

const calendarSchema = new mongoose.Schema({
    name: String,
    description: String,
    id: String,
    eventType:{type:String, lowercase:true},
    date: Date,
})

const taskSchema = new mongoose.Schema({
    name: String,
    taskMem1: String,
    taskMem2: String,
    taskMem3: String,
    assignedTask1: String,
    assignedTask2: String,
    assignedTask3: String,
    dueDate: Date,
    dueTime: String,
})

// PASSPORT COOKIES AND SESSIONS

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// INITIALIZE SCHEMAS
const User = new mongoose.model("User", userSchema);
const Admin = new mongoose.model("Admin", adminSchema);
const Appointment = new mongoose.model("Appointment", consultationSchema);
const Case = new mongoose.model("Case", caseSchema);
const Member = new mongoose.model("Member", memberSchema);
const Event = new mongoose.model("Event", eventSchema);
const Agenda = new mongoose.model("Agenda", agendaSchema);
const Report = new mongoose.model("Report", reportSchema);
const Project = new mongoose.model("Project", projectSchema);
const Update = new mongoose.model("Update", updateSchema);
const Invoice = new mongoose.model("Invoice", invoiceSchema);
const Diary = new mongoose.model("Diary", calendarSchema)
const Task = new mongoose.model("Task", taskSchema);
const InvoiceArchive = new mongoose.model("InvoiceArchive", fileSchema)
const ReportFile = new mongoose.model('ReportFile', fileSchema);
const Image = new mongoose.model('Image', fileSchema);
const ProjectFile = new mongoose.model('ProjectFile', fileSchema);
const GovCase = new mongoose.model('GovCase', fileSchema);
const FahmCase = new mongoose.model('FahmCase', fileSchema);
const CourtCase = new mongoose.model('CourtCase', fileSchema);

passport.use(User.createStrategy());

passport.serializeUser((user, done)=>{
    done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});
// PASSPORT GOOGLE AND TWITTER STRATEGIES

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "https://localhost:3000/auth/google/dashboard",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id, username: profile.emails[0].value },  (err, user) => {
            return cb(err, user);
        });
    }
));

passport.use(new TwitterStrategy({
        consumerKey: process.env.TWITTER_CONSUMER_KEY,
        consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
        callbackURL: "https://localhost:3000/auth/twitter/dashboard",
    },
    function(token, tokenSecret, profile, cb) {
        User.findOrCreate({ twitterId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

// GET ROUTES

// HOMEPAGE

app.get("/", (req, res)=>{
    res.render("webpages/index", {user:req.user});
});

// GOOGLE OAUTH

app.get('/auth/google',
    passport.authenticate("google", { scope: ['profile', 'email']
        }
    ));

app.get('/auth/google/dashboard', passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        // Successful authentication, redirect dashboard.
        req.flash('success', 'Welcome To Sigani Associates');
        res.redirect('/dashboard');
    });

app.get('/auth/twitter',
    passport.authenticate('twitter')
);

app.get('/auth/twitter/dashboard',
    passport.authenticate('twitter', { failureRedirect: '/login' }),
    (req, res) => {
        // Successful authentication, redirect dashboard.
        req.flash('success', 'Welcome To Sigani Associates');
        res.redirect('/dashboard');
    });

// DASHBOARD GET ROUTE

app.get("/dashboard", async(req, res)=>{
    if(req.isAuthenticated()){
        User.findOne({_id:req.user._id.toString()}, (err,user)=>{
            if(user) {
                Appointment.find({mailAddress: user.username}, (err, plans) => {
                    Case.find({clientEmail: user.username}, (err, projects)=>{
                        res.render("dashboard", {
                            clientProjects: projects,
                            clientCases: projects.length,
                            dates: plans.length,
                            first: plans[0],
                            others: plans.slice(1, plans.length),
                            user: user,
                            alerts: req.flash()
                        })
                    });
                })
            }
        })

    } else {
        req.flash('error', 'Please Log In or Create An Account To Continue')
        res.redirect("/login");
    }
});

// FORGOT ROUTE

app.get('/forgot', (req, res)=>{
    if(req.isAuthenticated()){
        return res.redirect("/dashboard");
    } else {
        res.render("webPages/forgot", {
            user:req.user,
            token: req.params.token,
            alerts:req.flash()
        });
    }
});

// RESET GET ROUTE WITH TOKEN

app.get('/reset/:token', (req, res) => {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
            req.flash('error', 'Password reset token is invalid or has expired.');
            return res.redirect('/login');
        }
        res.render('webPages/reset', {
            user: req.user,
            token: req.params.token,
            alerts:req.flash()
        });
    });
});

// OTHER PAGE LINKS ABOUT THE COMPANY

app.get("/:page", (req, res)=>{
    switch(req.params.page){
        case "about":
            res.render("webPages/about");
            break
        case "blog":
            res.render("webPages/blog");
            break
        case "contact":
            res.render("webPages/contact");
            break
        case "login":
            res.render("webPages/login", {user:req.user, alerts: req.flash() });
            break
        case "portfolio":
            res.render("webPages/portfolio");
            break
        case "service":
            res.render("webPages/service");
            break
        case "single":
            res.render("webPages/single");
            break
        case "team":
            res.render("webPages/team");
            break
        case "admin":
            res.render('webPages/adminLogin');
            break
    }
});

// POST ROUTES

// LOGIN AND SIGN UP ROUTE

// ADMIN LOGIN ROUTE
app.post('/admin', (req, res)=>{

    const bigman = new Admin({
        username: req.body.username,
        password: req.body.password
    });

    const identity = bcrypt.hashSync(process.env.ADMIN_EMAIL, saltRounds);
    const code = bcrypt.hashSync(process.env.ADMIN_SECRET_CODE, saltRounds);
    const employee = bcrypt.hashSync(process.env.EMPLOYEE_EMAIL, saltRounds);
    const passcode = bcrypt.hashSync(process.env.EMPLOYEE_SECRET_CODE, saltRounds);

    const isName = bcrypt.compareSync(bigman.username, identity,  (err, result)=>{return result});
    const isCode = bcrypt.compareSync(bigman.password, code,  (err, result)=>{return result});
    const isEmployee = bcrypt.compareSync(bigman.username, employee,  (err, result)=>{return result});
    const isPasscode = bcrypt.compareSync(bigman.password, passcode,  (err, result)=>{return result});

    if(isName && isCode){

        bigman.isAdmin = true;
        bigman.role = "admin";

        bigman.save(err=>{
            if(err){
                res.redirect('/login')
            } else {
                req.session.userId = bigman._id;
                res.redirect("admin/adminDash");
            }
        })
    } else if (isEmployee && isPasscode) {
        bigman.isAdmin = true;
        bigman.role = "employee";
        bigman.save(err=>{
            if(err){
                res.redirect('/login')
            } else {
                req.session.userId = bigman._id;
                res.redirect('admin/adminDash');
            }
        })
    } else {
        req.flash('error', 'BEGONE!!!!!!')
        res.redirect('/login');
    }
});

app.post("/login", (req, res) => {
    if (req.body.formType === "signup") {
        User.register({username: req.body.username, email:req.body.email, clientType:req.body.clientType}, req.body.password, (err, user) => {
            if (err) {
                req.flash('error', 'Email Account Already Exists');
                res.redirect("/login");
            } else {
                passport.authenticate("local")(req, res,  () => {
                    req.flash("error", "Please finish setting up your profile for effective service")
                    res.redirect("/dashboard");
                });
            }
        });
    } else if (req.body.formType === "signin") {
        let sameUser = new User({
            email: req.body.email,
            password: req.body.password,
        });

        req.login(sameUser, (err) => {
            if (err) {
                res.redirect('/login');
            } else {
                passport.authenticate("local", {failureRedirect: '/login', FailureFlash:req.flash('error', 'Try Again or Create An Account')})(req, res, function () {
                    req.flash('success', "Welcome Back. Pick Up Where You Left Off");
                    res.redirect("/dashboard");
                });
            }
        });
    }
});

// LOGOUT ROUTE THAT DESTROYS COOKIES

app.post('/logout', (req, res, next)=>{
    req.logout((err) => {
        if (err) { return next(err); }
        req.flash('success', "See you next time.");
        res.redirect('/login');
    });
});

// PASSWORD RESET CONTROL FLOW

// FORGOT PASSWORD, SEND EMAIL WITH TOKEN ROUTE

app.post('/forgot', (req, res, next)=>{
    async.waterfall([
        (done) => {
            crypto.randomBytes(20, (err, buf)=>{
                const token = buf.toString('hex');
                done(err, token);
            });
        },
        (token, done) => {
            User.findOne({username:req.body.username}, (err,user)=>{
                if(!user){
                    req.flash('error', "That Account doesn't exist. Try Again");
                    return res.redirect("/forgot");
                }
                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now()+3600000;
                user.save((err)=>{
                    done(err, token, user);
                });
            });
        },
        (token, user, done) => {
            const reset_url = 'https://' + req.headers.host + '/reset/' + token;
            const mailOptions = {
                from: process.env.AUTH_EMAIL,
                to: user.username,
                subject: "RESET YOUR PASSWORD.",
                text: "Your request for a password reset has been received.\n\n" +
                    "If you requested to change your password, please click on the following link within one hour-\n\n" + reset_url + "\n\n " +
                    "If you did not seek to change your password, you can ignore this email"
            }

            transporter.sendMail(mailOptions, (err) => {
                if (err) {
                    req.flash('error', 'An error has occurred. Please Try Again')
                }
                req.flash('success',"A link has been sent to your email with a reset token.");
                done(err, "Sent");
            });
        }
    ], (err) => {
        if(err) return next(err);
        res.redirect('/forgot');
    });
});

// PASSWORD RESET ROUTE

app.post('/reset/:token',  async(req, res)=>{
    async.waterfall([
        (done) => {
            User.findOne({
                    resetPasswordToken: req.params.token,
                    resetPasswordExpires:{$gt:Date.now()}}
                ,(err,user)=>{
                    if(!user){
                        req.flash('error', 'This token is invalid or has expired. Try Again');
                        return res.redirect('/forgot');
                    }
                    if(req.body.password === req.body.confirm){
                        user.setPassword(req.body.password, (err)=>{
                            user.resetPasswordToken = undefined;
                            user.resetPasswordExpires = undefined;
                            user.save((err)=>{
                                req.logIn(user, (err)=>{
                                    done(err,user);
                                    req.flash('success', 'Your Password has been changed successfully. Welcome Back.');
                                    res.redirect('/dashboard');
                                });
                            });
                        });
                    } else if (req.body.password !== req.body.confirm) {
                        req.flash('error', "Passwords Don't Match. Try Again");
                        res.redirect('/reset/' + req.params.token);
                    }
                });
        },
        (user, done) => {
            const successmail = {
                to:user.username,
                from: process.env.AUTH_EMAIL,
                subject: "YOUR PASSWORD HAS BEEN CHANGED",
                text: 'Hello,\n\n' +
                    'This is a confirmation that the password for your account ' + user.username + ' has just been changed.\n'
            };
            transporter.sendMail(successmail, (err)=>{
                done(err)
            });
        }
    ], (err)=>{
        res.redirect('/login');
    });
});

// THIS PART IS FOR THE CLIENT DASHBOARD
app.get('/dashboard/addAppointment', (req,res)=>{
    res.render('addAppointment')
})

app.post('/dashboard', client_upload,(req, res)=>{
    const details = {
        name: req.body.fname,
        phone: req.body.phone,
        mailAddress: req.body.mail,
        date: req.body.dateTime,
        time: req.body.masaa,
        area: req.body.area,
        purpose: req.body.purpose,
        files : req.files.map(file => ({ filename: file.originalname, path: file.path, originalname: file.originalname }))
    };
    Appointment.find({time:details.time, date:details.date}, (err,meetings)=>{
        const matchingtimes = meetings.filter(meeting => meeting.time === details.time);
        const matchingdates = meetings.filter(meeting => meeting.date === details.date);

        if((matchingtimes.length + matchingdates.length) > 0){
            req.flash('error', 'We currently have appointments  at the time you have chosen. Please choose another time')
            res.redirect('/dashboard')
        } else {
            const appointment = new Appointment(details)
            appointment.save(err =>{
                if (err){
                    req.flash('error', "Something went wrong. Please try again or give us a call.");
                } else {
                    req.flash('success', "Appointment successfully booked. See you there, " + req.body.fname);
                    res.redirect("/dashboard")
                }
            })
        }
    })
});

// THIS PART IS FOR THE  ADMIN PAGE GET ROUTES ONLY
app.get('/admin/adminDash', (req, res)=>{
    const { userId } = req.session;
    Admin.findById(userId, (err,around)=>{
        if(around){
            Appointment.find({}, (err, data) => {
                Project.find({$or: [{pStatus: "open"}, {pStatus: "pending"}]}, (err, project) => {
                    Agenda.find({}, (err, agenda) => {
                        Update.find({}, (err, update) => {
                            Case.find({}, (err,files)=>{
                                res.render('admin/adminDash', {
                                    alerts: req.flash(),
                                    agenda: agenda,
                                    project: project,
                                    data: data.slice(1, data.length),
                                    first: data[0],
                                    update: update,
                                    news: update.length,
                                    visitors: data.length,
                                    jobs: project.length,
                                    around: around,
                                    files:files
                                });
                            });
                        });
                    });
                });
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect('/login')
        }
    })
});

app.get('/adminDash/addCase', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addCase');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/diaryEntry', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/diaryEntry');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/addMember', (req, res)=>{
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addMember');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/addEvent', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addEvent');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/addInvoice', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addInvoice');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/addCaseReport', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addCaseReport');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/addProject', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addProject');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/addAgenda', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addAgenda');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/addUpdate', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addUpdate');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/addTask', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            res.render('admin/addContent/addTask');
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/updateProject/:id', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            var userId = req.params.id;
            Project.findById(userId, (err, data) => {
                if (err) {
                    console.log("Doesn't exist");
                } else {
                    res.render('admin/updateProject', {editData: data})
                }
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/calendar', (req, res)=>{
    const { userId } = req.session;
    Admin.findById(userId, (err, around)=> {
        if (around) {
            Appointment.find({}, (err, data) => {
                Diary.find({}, (err, diary)=>{
                    res.render('admin/calendar', {data: data, count: data.length, stuff:diary});
                })
            })
        } else {
            req.flash('error', "Get lost")
            res.redirect('/login')
        }
    });
});

app.get('/adminDash/email', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                res.render('admin/email', {data: data, count: data.length, section: req.params.section,});
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/reach', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                Member.find({}, (err, person) => {
                    res.render('admin/reach', {person: person, count: data.length, section: req.params.section,});
                });
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/invoice', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                Invoice.find({}, (err, invoice) => {
                    res.render('admin/invoice', {
                        data: data,
                        count: data.length,
                        invoice: invoice,
                    });
                });
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/profile/:worker', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                Member.find({full_name: req.params.worker}, (err, foundItem) => {
                    res.render('admin/profile', {
                        delete: req.params.worker,
                        mail: foundItem.mail_name,
                        profession: foundItem.occupation,
                        phone: foundItem.user_phone,
                        bio: foundItem.user_bio,
                        description: foundItem.job_bio,
                        act1: foundItem.user_fun1,
                        act2: foundItem.user_fun2,
                        act3: foundItem.user_fun3,
                        foundItem:foundItem,
                        count: data.length
                    });
                });
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/projects', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                Project.find({}, (err, project) => {
                    res.render('admin/projects', {
                        project: project,
                        data: data,
                        count: data.length,
                        section: req.params.section,
                        around: around.role,
                    });
                })
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/caseFiles', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                Case.find({}, (err, cases) => {
                    res.render('admin/caseFiles', {cases: cases, count: data.length, section: req.params.section,around:around.role});
                });
            })
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/caseReports', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                Report.find({}, (err, report) => {
                    res.render('admin/caseReports',
                        {report: report, data: data, count: data.length, section: req.params.section,});
                });
            })
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/widgets',  (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, async (err, around) => {
        if (around) {
            let appointments = await Appointment.find({});
            let events = await Event.find({});
            let agendas = await Agenda.find({});
            let jobs = await Task.find({});

            res.render('admin/widgets', {
                count: appointments.length,
                task: events,
                leo: agendas,
                around:around.role,
                jobs:jobs
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

// THIS PART IS FOR THE  ADMIN PAGE POST ROUTES ONLY
app.post('/adminDash', (req, res)=>{
    const newUpdate = new Update({
        uName: req.body.uName,
        uNews: req.body.uNews,
    });

    newUpdate.save(err =>{
        if(err){
            return err
        } else {
            res.redirect('/adminDash')
        }
    });
});

app.post('/adminDash/caseFiles', (req, res)=>{
    const newCase = new Case({
        caseTitle: req.body.caseTitle,
        caseType:  req.body.caseType,
        orgName: req.body.orgName,
        clientEmail: req.body.clientEmail,
        lawyer1 : req.body.lawyer1,
        lawyer2 : req.body.lawyer2,
        lawyer3 : req.body.lawyer3,
        lawyer4 : req.body.lawyer4,
        lawyer5 : req.body.lawyer5,
        lawyer6 : req.body.lawyer6,
        lawyer7 : req.body.lawyer7,
        lawyer8 : req.body.lawyer8,
        job1: req.body.job1,
        job2: req.body.job2,
        job3: req.body.job3,
        job4: req.body.job4,
        job5: req.body.job5,
        job6: req.body.job6,
        job7: req.body.job7,
        job7: req.body.job7,
        lawyerNumber: req.body.lawyerNumber,
    });

    newCase.save(err =>{
        if(err){
            req.flash('error', "Something went wrong. Please Try Again.")
        } else {
            req.flash('succes', "Amazing")

            res.redirect('/adminDash/caseFiles')
        }
    })
});

app.post('/adminDash/reach', (req, res)=>{
    const member = new Member({
        full_name: req.body.full_name,
        mail_name: req.body.mail_name,
        occupation: req.body.occupation,
        user_phone: req.body.user_phone,
        user_bio: req.body.user_bio,
        job_bio: req.body.job_bio,
        user_fun1: req.body.user_fun1,
        user_fun2: req.body.user_fun2,
        user_fun3: req.body.user_fun3,
    });

    member.save(err =>{
        if(err){
            console.log(err)
        } else {
            res.redirect('/adminDash/reach')
        }
    })
});

app.post('/adminDash/widgets', (req, res)=>{
    switch(req.body.formType){
        case "agenda":
            const newAgenda = new Agenda({
                aName: req.body.aName,
                aPriority: req.body.aPriority,
                aTime: req.body.aTime,
            });

            newAgenda.save(err =>{
                if(err){
                    console.log(err)
                } else {
                    res.redirect('/adminDash/widgets')
                }
            });
            break;
        case "event":
            const task = new Event({
                eventType: req.body.eventType,
                eventDate: req.body.eventDate,
                eventTime: req.body.eventTime
            });

            task.save(err => {
                if (err) {
                    console.log(err)
                } else {
                    res.redirect('/adminDash/widgets')
                }
            });
            break;
        case "task":
            const job = new Task({
                name:req.body.assignTask,
                taskMem1: req.body.taskMem1,
                taskMem2: req.body.taskMem2,
                taskMem3: req.body.taskMem3,
                assignedTask1: req.body.assignedTask1,
                assignedTask2: req.body.assignedTask2,
                asssignedTask3: req.body.asssignedTask3,
                dueDate: req.body.dueDate,
                dueTime: req.body.dueTime,
            })
            job.save(err=>{
                if(err){
                    console.log(err);
                } else {
                    res.redirect('/adminDash/widgets')
                }
            })
            break
    }
});

app.post('/adminDash/caseReports', (req, res)=>{
    const report = new Report({
        cnum: req.body.cnum,
        cintro: req.body.cintro,
        cbio: req.body.cintro,
        cname: req.body.cname,
        cmail: req.body.cmail,
        cphone: req.body.cphone,
        cStatus: req.body.cStatus
    });

    report.save(err => {
        if(err){
            console.log(err);
        } else {
            res.redirect('/adminDash/caseReports')
        }
    });
});

app.post('/adminDash/projects', (req, res)=>{
    const newProject = new Project({
        ctitle: req.body.ctitle,
        mem1: req.body.mem1,
        mem2: req.body.mem2,
        mem3: req.body.mem3,
        mem4: req.body.mem4,
        mem5: req.body.mem5,
        mem6: req.body.mem6,
        mem7: req.body.mem7,
        mem8: req.body.mem8,
        task1 : req.body.task1,
        task2 : req.body.task2,
        task3 : req.body.task3,
        task4 : req.body.task4,
        task5 : req.body.task5,
        task6 : req.body.task6,
        task7 : req.body.task7,
        task8 : req.body.task8,
    });

    newProject.save(err=>{
        if(err){
            console.log(err);
        } else {
            res.redirect('/adminDash/projects')
        }
    })

});

app.post('/adminDash/invoice', (req,res)=>{
    const newInvoice = new Invoice({
        cname: req.body.cname,
        cEmail:req.body.cEmail,
        clocale:req.body.clocale,
        cphone:req.body.cphone,
        cid: req.body.cid,
        cissue: req.body.cissue,
        serv1: req.body.serv1, quan1: req.body.quan1, unit1: req.body.unit1,
        serv2: req.body.serv2, quan2: req.body.quan2, unit2: req.body.unit2,
        serv3: req.body.serv3, quan3: req.body.quan3, unit3: req.body.unit3,
        serv4: req.body.serv4, quan4: req.body.quan4, unit4: req.body.unit4,
        serv5: req.body.serv5, quan5: req.body.quan5, unit5: req.body.unit5,
        serv6: req.body.serv6, quan6: req.body.quan6, unit6: req.body.unit6,
        serv7: req.body.serv7, quan7: req.body.quan7, unit7: req.body.unit7,
        serv8: req.body.serv8, quan8: req.body.quan8, unit8: req.body.unit8,
        serv9: req.body.serv9, quan9: req.body.quan9, unit9: req.body.unit9,
        serv10: req.body.serv10, quan10: req.body.quan10, unit10: req.body.unit10,
        serv11: req.body.serv11, quan11: req.body.quan11, unit11: req.body.unit11,
        ctax: req.body.ctax,
    });
    newInvoice.save(err => {
        if(err){
            console.log("Error incurred");
        } else {
            res.redirect("/adminDash/invoice");
        }
    });

});

app.post('/adminDash/email', email_upload, (req, res)=>{

    const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: req.body.receiver,
        cc: req.body.ccopy,
        bcc: req.body.bcopy,
        subject: req.body.subject,
        text: req.body.textmessage,
        attachments: req.files.map(file=>({filename: file.originalname, path: file.path}))
    };

    transporter.sendMail(mailOptions, (err, data)=> {
        if (err) {
            req.flash('error', 'Something went wrong. Check Your Internet Connection')
        } else {
            req.flash('success', 'email sent successfully')
            res.redirect('/adminDash/email')
        }
    });
});

app.get('/adminDash/invoiceStuffsearch', (req,res)=>{
    let query = req.query.invoiceSearch;
    try {
        InvoiceArchive.find({filename:{'$regex':query,$options:'i'}},(err,invoiceStuff)=>{
            if(err){
                console.log(err);
            }else{
                res.render('admin/caseFiles/invoiceStuff',{invoiceStuff:invoiceStuff, section:req.params.section});
            }
        })
    } catch (error) {
        console.log(error);
    }
})

app.get('/adminDash/courtFilessearch', (req,res)=>{
    let query = req.query.courtSearch;
    try {
        CourtCase.find({filename:{'$regex':query,$options:'i'}},(err,files)=>{
            if(err){
                console.log(err);
            }else{
                res.render('admin/caseFiles/courtFiles',{files:files, section:req.params.section});
            }
        })
    } catch (error) {
        console.log(error);
    }
})

app.get('/adminDash/fahmFilessearch', (req,res)=>{
    let query = req.query.fahmSearch;
    try {
        FahmCase.find({filename:{'$regex':query,$options:'i'}},(err,files)=>{
            if(err){
                console.log(err);
            }else{
                res.render('admin/caseFiles/fahmFiles',{files:files, section:req.params.section});
            }
        })
    } catch (error) {
        console.log(error);
    }
})

app.get('/adminDash/govFilessearch', (req,res)=>{
    let query = req.query.govSearch;
    try {
        GovCase.find({filename:{'$regex':query,$options:'i'}},(err,files)=>{
            if(err){
                console.log(err);
            }else{
                res.render('admin/caseFiles/govFiles',{files:files, section:req.params.section});
            }
        })
    } catch (error) {
        console.log(error);
    }
})

app.get('/adminDash/projectsearch', (req,res)=>{
    let query = req.query.projectSearch;
    try {
        ProjectFile.find({filename:{'$regex':query,$options:'i'}},(err,files)=>{
            if(err){
                console.log(err);
            }else{
                res.render('admin/caseFiles/projectFiles',{files:files, section:req.params.section});
            }
        })
    } catch (error) {
        console.log(error);
    }
})

app.get('/adminDash/imagesearch', (req,res)=>{
    let query = req.query.imageSearch;
    try {
        Image.find({filename:{'$regex':query,$options:'i'}},(err,images)=>{
            if(err){
                console.log(err);
            }else{
                res.render('admin/caseFiles/images',{images:images, section:req.params.section});
            }
        })
    } catch (error) {
        console.log(error);
    }
})

app.get('/adminDash/reportFilessearch', (req,res)=>{
    let query = req.query.reportSearch;
    try {
        ReportFile.find({filename:{'$regex':query,$options:'i'}},(err,reports)=>{
            if(err){
                console.log(err);
            }else{
                res.render('admin/caseFiles/reportFiles',{reports:reports, section:req.params.section});
            }
        })
    } catch (error) {
        console.log(error);
    }
})

// THESE ARE THE DELETE ROUTES FOR SIGANI
app.delete('/delete/:id', (req, res)=>{

    Appointment.findByIdAndRemove(req.params.id, err =>{
        Agenda.findByIdAndRemove(req.params.id, err=>{
            Event.findByIdAndRemove(req.params.id, err=>{
                Update.findByIdAndRemove(req.params.id, err=>{
                    Case.findByIdAndRemove(req.params.id, err=>{
                        Project.findByIdAndRemove(req.params.id, err=>{
                            Invoice.findByIdAndRemove(req.params.id, err=>{
                                if(!err){
                                    req.flash('success', 'Operation Successfully Completed')
                                    res.redirect(req.headers.referer);
                                }
                            });
                        });
                    });
                });
            });
        });
    });
});

// THIS IS THE UPDATE ROUTE FOR SIGANI USING POST
app.post('/adminDash/updateProject/:id', async(req, res)=>{
    const updateObject = {
        ctitle: req.body.ctitle,
        mem1: req.body.mem1,
        mem2: req.body.mem2,
        mem3: req.body.mem3,
        mem4: req.body.mem4,
        mem5: req.body.mem5,
        mem6: req.body.mem6,
        mem7: req.body.mem7,
        mem8: req.body.mem8,
        task1 : req.body.task1,
        task2 : req.body.task2,
        task3 : req.body.task3,
        task4 : req.body.task4,
        task5 : req.body.task5,
        task6 : req.body.task6,
        task7 : req.body.task7,
        task8 : req.body.task8,
    }
    Project.findByIdAndUpdate({ _id: req.params.id }, { $set: updateObject}, (err)=>{
        if(err){
            console.log(err);
        } else {
            res.redirect('/adminDash/projects')
        }
    })
});

// THIS IS THE GET ROUTE FOR THE 404 ERROR
//
// app.use((req, res, next) => {
//    res.status(404).send("Sorry can't find that!")
// });

// SERVER CREATION FOR IT TO RUN

app.get('/adminDash/archives', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                res.render('admin/archives', {data: data, count: data.length, section: req.params.section});
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/invoiceStuff', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                InvoiceArchive.find({}, (err,invoiceStuff)=>{
                    res.render('admin/caseFiles/invoiceStuff', {
                        data: data,
                        count: data.length,
                        section: req.params.section,
                        invoiceStuff:invoiceStuff
                    });

                })
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/projectFiles', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                ProjectFile.find({}, (err, files)=>{
                    res.render('admin/caseFiles/projectFiles', {data: data, count: data.length, section: req.params.section, files:files});
                })
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/reportFiles', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                ReportFile.find({}, (err,reports)=>{
                    res.render('admin/caseFiles/reportFiles', {
                        data: data,
                        count: data.length,
                        section: req.params.section,
                        reports:reports
                    });
                })
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/images', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                Image.find({}, (err,images)=>{
                    res.render('admin/caseFiles/images', {data: data, count: data.length, section: req.params.section, images:images});
                })
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.post('/adminDash/images', function(req, res) {
    image_upload(req, res, function(err) {
        if (err) {
            return res.status(400).json({ message: err.message });
        }

        const files = req.files;

        for (let i = 0; i < files.length; i++) {
            const file = new Image({
                filename: files[i].filename,
                path: files[i].path,
                originalName: files[i].originalname
            });

            file.save();
        }
        res.redirect('/adminDash/images')
    });
});

app.post('/adminDash/projectFiles', function(req, res, next) {
    project_upload(req, res, function(err) {
        if (err) {
            return res.status(400).json({ message: err.message });
        }

        const files = req.files;

        for (let i = 0; i < files.length; i++) {
            const file = new ProjectFile({
                filename: files[i].filename,
                path: files[i].path,
                originalName: files[i].originalname
            });

            file.save(err=>{});
        }
        res.redirect('/adminDash/projectFiles')
    });
});

app.post('/adminDash/reportFiles', function(req, res, next) {
    report_upload(req, res, function(err) {
        if (err) {
            return res.status(400).json({ message: err.message });
        }

        const files = req.files;

        for (let i = 0; i < files.length; i++) {
            const file = new ReportFile({
                filename: files[i].filename,
                path: files[i].path,
                originalName: files[i].originalname
            });

            file.save();
        }
        res.redirect('/adminDash/reportFiles')
    });
});

app.post('/adminDash/invoiceStuff', function(req, res, next) {
    invoice_upload(req, res, function(err) {
        if (err) {
            return res.status(400).json({ message: err.message });
        }

        const files = req.files;

        for (let i = 0; i < files.length; i++) {
            const file = new InvoiceArchive({
                filename: files[i].filename,
                path: files[i].path,
                originalName: files[i].originalname
            });

            file.save(err=>{});
        }
        res.redirect('/adminDash/invoiceStuff')
    });
});

app.get('/adminDash/GovFiles', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                GovCase.find({}, (err,files)=>{
                    res.render('admin/caseFiles/govFiles', {
                        data: data,
                        count: data.length,
                        section: req.params.section,
                        files:files
                    });
                })
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/FahmFiles', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                FahmCase.find({}, (err,files)=>{
                    res.render('admin/caseFiles/fahmFiles', {
                        data: data,
                        count: data.length,
                        section: req.params.section,
                        files:files
                    });
                })
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/adminDash/CourtFiles', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                CourtCase.find({},(err,files)=>{
                    res.render('admin/caseFiles/courtFiles', {
                        data: data,
                        count: data.length,
                        section: req.params.section,
                        files:files
                    });
                })
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.post('/adminDash/GovFiles', function(req, res, next) {
    gov_upload(req, res, function(err) {
        if (err) {
            return res.status(400).json({ message: err.message });
        }

        const files = req.files;

        for (let i = 0; i < files.length; i++) {
            const file = new GovCase({
                filename: files[i].filename,
                path: files[i].path,
                originalName: files[i].originalname
            });

            file.save(err=>{});
        }
        res.redirect('/adminDash/govFiles')
    });
});

app.post('/adminDash/FahmFiles', function(req, res, next) {
    fahm_upload(req, res, function(err) {
        if (err) {
            return res.status(400).json({ message: err.message });
        }

        const files = req.files;

        for (let i = 0; i < files.length; i++) {
            const file = new FahmCase({
                filename: files[i].filename,
                path: files[i].path,
                originalName: files[i].originalname
            });

            file.save(err=>{});
        }
        res.redirect('/adminDash/fahmFiles')
    });
});

app.post('/adminDash/CourtFiles', function(req, res, next) {
    court_upload(req, res, function(err) {
        if (err) {
            return res.status(400).json({ message: err.message });
        }

        const files = req.files;

        for (let i = 0; i < files.length; i++) {
            const file = new CourtCase({
                filename: files[i].filename,
                path: files[i].path,
                originalName: files[i].originalname
            });

            file.save(err=>{});
        }
        res.redirect('/adminDash/courtFiles')
    });
});

app.post('/adminDash/projects/:id', userProject_upload, async(req,res)=>{
    const updatedDocument = await Project.findOneAndUpdate({ _id: req.params.id }, { $push: { files: req.files.map(file=>({filename: file.originalname, path: file.path, originalname: file.originalname})) } }, { new: true });

    res.redirect('/adminDash/projects')
})

app.get('/download/projects/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/projects/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/reports/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/reports/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/invoices/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/invoices/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/gov/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/gov/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/images/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/images/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/family/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/family/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/court/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/court/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/userProjects/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/userProjects/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/clientFiles/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/clientFiles/' + filename;
    res.download(file); // Set disposition and send it.
});

app.get('/download/orgFiles/:filename', function(req, res){
    var filename = req.params.filename;
    var file = __dirname + '/uploads/orgFiles/' + filename;
    res.download(file); // Set disposition and send it.
});

app.post('/adminDash/done/task1', async(req,res)=>{
    filter = {task1: req.body.task1}
    update = {task1Completed: true}
    Project.findOneAndUpdate(filter,update,
        (err, Task1) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/projects')
            }
        }
    );
});

app.post('/adminDash/done/task2', async(req,res)=>{
    filter = {task2: req.body.task2}
    update = {task2Completed: true}
    Project.findOneAndUpdate(filter,update,
        (err, Task2) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/projects')
            }
        }
    );
});

app.post('/adminDash/done/task3', async(req,res)=>{
    filter = {task3: req.body.task3}
    update = {task3Completed: true}
    Project.findOneAndUpdate(filter,update,
        (err, Task3) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/projects')
            }
        }
    );
});

app.post('/adminDash/done/task4', async(req,res)=>{
    filter = {task4: req.body.task4}
    update = {task4Completed: true}
    Project.findOneAndUpdate(filter,update,
        (err, Task4) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/projects')
            }
        }
    );
});

app.post('/adminDash/done/task5', async(req,res)=>{
    filter = {task5: req.body.task5}
    update = {task5Completed: true}
    Project.findOneAndUpdate(filter,update,
        (err, Task5) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/projects')
            }
        }
    );
});

app.post('/adminDash/done/task6', async(req,res)=>{
    filter = {task6: req.body.task6}
    update = {task6Completed: true}
    Project.findOneAndUpdate(filter,update,
        (err, Task6) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/projects')
            }
        }
    );
});

app.post('/adminDash/done/task7', async(req,res)=>{
    filter = {task7: req.body.task7}
    update = {task7Completed: true}
    Project.findOneAndUpdate(filter,update,
        (err, Task7) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/projects')
            }
        }
    );
});

app.post('/adminDash/done/task8', async(req,res)=>{
    filter = {task8: req.body.task8}
    update = {task8Completed: true}
    Project.findOneAndUpdate(filter,update,
        (err, Task8) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/projects')
            }
        }
    );
});

app.post('/adminDash/done/job1', async(req,res)=>{
    filter = {job1: req.body.job1}
    update = {job1Completed: true}
    Case.findOneAndUpdate(filter,update,
        (err, Job1) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/caseFiles')
            }
        }
    );
});

app.post('/adminDash/done/job2', async(req,res)=>{
    filter = {job2: req.body.job2}
    update = {job2Completed: true}
    Case.findOneAndUpdate(filter,update,
        (err, Job2) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/caseFiles')
            }
        }
    );
});

app.post('/adminDash/done/job3', async(req,res)=>{
    filter = {job3: req.body.job3}
    update = {job3Completed: true}
    Case.findOneAndUpdate(filter,update,
        (err, Job3) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/caseFiles')
            }
        }
    );
});

app.post('/adminDash/done/job4', async(req,res)=>{
    filter = {job4: req.body.job4}
    update = {job4Completed: true}
    Case.findOneAndUpdate(filter,update,
        (err, Job4) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/caseFiles')
            }
        }
    );
});

app.post('/adminDash/done/job5', async(req,res)=>{
    filter = {job5: req.body.job5}
    update = {job5Completed: true}
    Case.findOneAndUpdate(filter,update,
        (err, Job5) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/caseFiles')
            }
        }
    );
});

app.post('/adminDash/done/job6', async(req,res)=>{
    filter = {job6: req.body.job6}
    update = {job6Completed: true}
    Case.findOneAndUpdate(filter,update,
        (err, Job6) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/caseFiles')
            }
        }
    );
});

app.post('/adminDash/done/job7', async(req,res)=>{
    filter = {job7: req.body.job7}
    update = {job7Completed: true}
    Case.findOneAndUpdate(filter,update,
        (err, Job7) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/caseFiles')
            }
        }
    );
});

app.post('/adminDash/done/job8', async(req,res)=>{
    filter = {job8: req.body.job8}
    update = {job8Completed: true}
    Case.findOneAndUpdate(filter,update,
        (err, Job8) => {
            if (err) {
                console.error(err);
            } else {
                res.redirect('/adminDash/caseFiles')
            }
        }
    );
});

app.post('/adminDash/calendar' ,async(req, res)=>{

    const newEntry = new Diary({
        name: req.body.dname,
        description: req.body.describe,
        date: req.body.dDate,
        eventType: req.body.dType,
    })

    if (newEntry.eventType === "work"){
        newEntry.eventType = "birthday"
    }
    newEntry.save(err => {
        if(err){
            console.log(err)
        } else {
            res.redirect('/adminDash/calendar')
        }
    })
})

app.get('/dashboard/clientCases', (req,res)=>{
    if(req.isAuthenticated()){
        User.findOne({_id:req.user._id.toString()}, (err,user)=>{
            if(user) {
                Case.find({clientEmail: user.username}, (err, cases) => {
                    res.render("clientCases", {
                        cases: cases,
                        user: user,
                        alerts: req.flash()
                    });
                })
            }
        })

    } else {
        req.flash('error', 'Please Log In or Create An Account To Continue')
        res.redirect("/login");
    }
})

app.get('/adminDash/clientele', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                User.find({}, (err, clientele) => {
                    res.render('admin/clientele', {clientele: clientele, count: data.length, section: req.params.section,});
                });
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

app.get('/dashboard/userIdentity', (req,res)=>{
    if(req.isAuthenticated()){
        User.findOne({_id:req.user._id.toString()}, (err,user)=>{
            if(user) {
                res.render("userIdentity", {
                    user: user,
                    alerts: req.flash()
                });
            }
        })
    } else {
        req.flash('error', 'Please Log In or Create An Account To Continue')
        res.redirect("/login");
    }
})

app.get('/dashboard/updateProfile/:id', (req, res)=>{
    if(req.isAuthenticated()){
        User.findOne({_id:req.user._id.toString()}, (err, user)=>{
            if(user){
                User.findById({_id:req.params.id}, (err, editData)=>{
                    if(editData){
                        res.render('updateProfile', {editData:editData, user:user})
                    }
                })
            }
        })
    }
})

app.post('/dashboard/updateProfile/:id', orgFiles_upload,  async(req,res)=>{
    if(req.isAuthenticated()){
        User.findOne({_id:req.user._id.toString()}, async(err,user)=>{
            if(user){
                let updateObject = {
                    email: req.body.yourName,
                    occupation: req.body.yourJob,
                    phoneNumber: req.body.yourPhone,
                    idNumber: req.body.yourID,
                    passportNumber: req.body.yourPassport,
                    postalAddress: req.body.postAddress,
                    physicalAddress: req.body.physicalAddress,
                    kraPin: req.body.kraPin,
                    files: req.files.map(file=>({filename: file.originalname, path: file.path, originalname: file.originalname}))
                }
                User.findByIdAndUpdate({ _id: req.params.id }, { $set: updateObject},{$push:{files:req.files.map(file=>({filename: file.originalname, path: file.path, originalname: file.originalname}))}}, (err)=>{
                    if(err){
                        console.log(err);
                    } else {
                        res.redirect('/dashboard/userIdentity')
                    }
                })
            }
        })
    }
})

app.get('/adminDash/eachUser/:client', (req, res)=> {
    const { userId } = req.session;
    Admin.findById(userId, (err, around) => {
        if (around) {
            Appointment.find({}, (err, data) => {
                User.find({email: req.params.client}, (err, user) => {
                    res.render('admin/eachUser', {
                        jina: req.params.client,
                        user:user[0],
                        count: data.length
                    });
                });
            });
        } else {
            req.flash('error', "Get lost")
            res.redirect("/login")
        }
    });
});

https.createServer(options, app).listen(3000, ()=>{
    console.log("Server started on port 3000");
});

// Remember to implement Argon2 for password encryption which is more superior compared to Bcrypt
