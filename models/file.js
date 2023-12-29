const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const fileSchema = new Schema({
    filename: String,
    path: String,
    originalName: String
});

module.exports = {
    InvoiceArchive :  mongoose.model("InvoiceArchive", fileSchema),
    ReportFile :  mongoose.model('ReportFile', fileSchema),
    Image :  mongoose.model('Image', fileSchema),
    ProjectFile :  mongoose.model('ProjectFile', fileSchema),
    GovCase :  mongoose.model('GovCase', fileSchema),
    FahmCase :  mongoose.model('FahmCase', fileSchema),
    CourtCase :  mongoose.model('CourtCase', fileSchema),
};