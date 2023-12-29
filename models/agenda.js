const mongoose = require('mongoose');
const Schema = mongoose.Schema;

function getSecondsToTomorrow(){
    let now = new Date();
    let tomorrow = new Date(now.getFullYear(), now.getMonth(), now.getDate()+1)
    let diff = tomorrow - now;
    return Math.round(diff/1000)
}

const agendaSchema = new mongoose.Schema({
    aName: String,
    aPriority: String,
    aTime: String,
    expireAt: {type: Date, expires: 43200}
});
agendaSchema.index({createdAt: 1},{expireAfterSeconds: getSecondsToTomorrow()});

module.exports = {
    Agenda : mongoose.model("Agenda", agendaSchema)
};
