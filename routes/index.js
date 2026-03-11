const express = require('express');
const router = express.Router();

// 首页
router.get('/', (req, res) => {
    if (req.isAuthenticated()) {
        if (req.user.role === 'admin' || req.user.role === 'superadmin') {
            return res.redirect('/admin');
        } else if (req.user.role === 'dispatcher') {
            return res.redirect('/dispatcher');
        }
    }
    res.render('index');
});

module.exports = router;
