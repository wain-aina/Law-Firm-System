const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const emailValid = require('./emailValidate')

const calendarSchema = new Schema({
    name: String,
    description: String,
    id: String,
    eventType:{type:String, lowercase:true},
    date: Date,
})

module.exports = {
    Diary : mongoose.model("Diary", calendarSchema)
};
