const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const emailValid = require('./emailValidate')
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");

const userSchema = new Schema({
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
        validate: [emailValid, 'Please fill a valid email address'],
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

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);
module.exports = User;

