const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const emailValid = require('./emailValidate')

const invoiceSchema = new Schema({
    cname: String, cEmail:{type: String, sparse: true, trim: true, lowercase: true, unique: false, require: true,
        validate: [emailValid, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    }, clocale:String, cid: String, cissue: String,cphone:Number,
    serv1:String, quan1: String, unit1: Number,
    serv2:String, quan2: String, unit2: Number,
    serv3:String, quan3: String, unit3: Number,
    serv4:String, quan4: String, unit4: Number,
    serv5:String, quan5: String, unit5: Number,
    serv6:String, quan6: String, unit6: Number,
    serv7:String, quan7: String, unit7: Number,
    serv8:String, quan8: String, unit8: Number,
    serv9:String, quan9: String, unit9: Number,
    serv10:String, quan10: String, unit10: Number,
    serv11:String, quan11: String, unit11: Number,
    ctax:Number,
});

module.exports = {
    Invoice: mongoose.model('Invoice', invoiceSchema),
    InvoiceArchive: mongoose.model('InvoiceArchive', invoiceSchema)
}