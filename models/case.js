const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const caseSchema = new Schema({
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

const Case = new mongoose.model("Case", caseSchema)
module.exports = Case;
