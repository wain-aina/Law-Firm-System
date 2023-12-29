const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const adminSchema = new Schema({
    username: String,
    isAdmin: {type:Boolean, default:false},
    role: {
        type: String,
        enum: ['employee', 'admin'],
        default: 'employee'
    },
    password: {type:String},
});

module.exports = mongoose.model('Admin', adminSchema);