const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcryptjs');
const { ensureAuthenticated } = require('../middleware/auth');
const { User } = require('../models');

// 登录页面
router.get('/login', (req, res) => {
    res.render('login', { is_profile: false });
});

// 登录处理
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        failureFlash: true
    })(req, res, next);
});

// 登出
router.get('/logout', ensureAuthenticated, (req, res) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});

// 个人中心
router.get('/profile', ensureAuthenticated, (req, res) => {
    res.render('login', { is_profile: true });
});

// 修改密码
router.post('/profile', ensureAuthenticated, async (req, res) => {
    const { old_password, new_password, confirm_password } = req.body;
    
    try {
        // 验证原密码
        const isMatch = await bcrypt.compare(old_password, req.user.password_hash);
        if (!isMatch) {
            req.flash('info', '原密码错误');
            return res.redirect('/profile');
        }
        
        // 验证新密码
        if (new_password !== confirm_password) {
            req.flash('info', '两次新密码不一致');
            return res.redirect('/profile');
        }
        
        if (!new_password) {
            req.flash('info', '新密码不能为空');
            return res.redirect('/profile');
        }
        
        // 更新密码
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(new_password, salt);
        
        await User.update(
            { password_hash: hash },
            { where: { id: req.user.id } }
        );
        
        req.flash('info', '密码修改成功，请重新登录');
        req.logout((err) => {
            res.redirect('/login');
        });
    } catch (error) {
        console.error(error);
        req.flash('info', '修改失败');
        res.redirect('/profile');
    }
});

module.exports = router;
