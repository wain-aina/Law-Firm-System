const mongoose = require('mongoose');
const Schema = mongoose.Schema;

function getSecondsToTomorrow(){
    let now = new Date();
    let tomorrow = new Date(now.getFullYear(), now.getMonth(), now.getDate()+1)
    let diff = tomorrow - now;
    return Math.round(diff/1000)
}

const updateSchema = new Schema({
    uName: String,
    uNews: String,
},{timestamps:true});
updateSchema.index({createdAt: 1},{expireAfterSeconds: getSecondsToTomorrow()});

module.exports = {
    Update : mongoose.model("Update", updateSchema)
};
