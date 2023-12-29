const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const projectSchema = new Schema({
    ctitle: String,
    mem1: String,
    mem2: String,
    mem3: String,
    mem4: String,
    mem5: String,
    mem6: String,
    mem7: String,
    mem8: String,
    task1: String,
    task1Completed: {type:Boolean,default:false},
    task2: String,
    task2Completed: {type:Boolean,default:false},
    task3: String,
    task3Completed: {type:Boolean,default:false},
    task4: String,
    task4Completed: {type:Boolean,default:false},
    task5: String,
    task5Completed: {type:Boolean,default:false},
    task6: String,
    task6Completed: {type:Boolean,default:false},
    task7: String,
    task7Completed: {type:Boolean,default:false},
    task8: String,
    task8Completed: {type:Boolean,default:false},
    files:[{
        filename: String,
        path: String,
        originalName: String
    }]
});

module.exports = {
    Project : mongoose.model("Project", projectSchema)
};
