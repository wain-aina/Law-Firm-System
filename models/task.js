const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const taskSchema = new Schema({
    name: String,
    taskMem1: String,
    taskMem2: String,
    taskMem3: String,
    assignedTask1: String,
    assignedTask2: String,
    assignedTask3: String,
    dueDate: Date,
    dueTime: String,
})

module.exports = {
    Task : mongoose.model("Task", taskSchema)
};