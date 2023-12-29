const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const emailValid = require('./emailValidate')

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
        validate: [emailValid, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    cStatus: String,
});

module.exports = {
    Report : mongoose.model("Report", reportSchema)
};
