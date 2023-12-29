const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const emailValid = require('./emailValidate')

const consultationSchema = new Schema({
    name: String,
    phone:  Number,
    mailAddress: {
        type: String,
        sparse: true,
        trim: true,
        lowercase: true,
        unique: false,
        require: true,
        validate: [emailValid, 'Please fill a valid email address'],
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

const Appointment = new mongoose.model("Appointment", consultationSchema)
module.exports = Appointment;
