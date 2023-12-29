const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const eventSchema = new Schema({
    eventType: String,
    eventDate: Date,
    eventTime: String,
});

module.exports = {
    Event : mongoose.model("Event", eventSchema)
};
