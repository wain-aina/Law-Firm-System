const express = require('express');
const router = express.Router({mergeParams: true});
const pages = require('../controllers/webPages');

router.get('/:page', pages.get_pages);

module.exports = router;