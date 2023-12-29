const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const emailValid = require('./emailValidate')

const memberSchema = new mongoose.Schema({
    full_name: String,
    mail_name:  {
        type: String,
        sparse: true,
        trim: true,
        lowercase: true,
        unique: false,
        require: true,
        validate: [emailValid, 'Please fill a valid email address'],
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

module.exports = {
    Member : mongoose.model("Member", memberSchema)
};
