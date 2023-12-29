const express = require('express');
const bodyParser = require("body-parser");

exports.get_pages = (req,res) => {
    switch (req.params.page) {
        case "about":
            res.render("webPages/about");
            break
        case "blog":
            res.render("webPages/blog");
            break
        case "contact":
            res.render("webPages/contact");
            break
        case "login":
            res.render("webPages/login", {user: req.user, alerts: req.flash()});
            break
        case "portfolio":
            res.render("webPages/portfolio");
            break
        case "service":
            res.render("webPages/service");
            break
        case "single":
            res.render("webPages/single");
            break
        case "team":
            res.render("webPages/team");
            break
        case "admin":
            res.render('webPages/adminLogin');
            break
    }
}