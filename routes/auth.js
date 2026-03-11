const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcryptjs');
const { ensureAuthenticated } = require('../middleware/auth');
const { User } = require('../models');

// 登录页面
router.get('/login', async (req, res) => {
    try {
        const userCount = await User.count();
        if (userCount === 0) {
            return res.redirect('/register');
        }
        res.render('login', { is_profile: false });
    } catch (error) {
        console.error(error);
        res.render('login', { is_profile: false });
    }
});

// 注册页面（仅首次）
router.get('/register', async (req, res) => {
    try {
        const userCount = await User.count();
        if (userCount > 0) {
            return res.redirect('/login');
        }
        res.render('register');
    } catch (error) {
        console.error(error);
        res.redirect('/login');
    }
});

// 注册处理（仅首次创建超级管理员）
router.post('/register', async (req, res) => {
    const { username, password, confirm_password } = req.body;
    try {
        const userCount = await User.count();
        if (userCount > 0) {
            return res.status(403).render('error', { message: '注册已关闭' });
        }
        if (!username || !password) {
            req.flash('info', '用户名和密码不能为空');
            return res.redirect('/register');
        }
        if (password !== confirm_password) {
            req.flash('info', '两次密码不一致');
            return res.redirect('/register');
        }

        const existing = await User.findOne({ where: { username } });
        if (existing) {
            req.flash('info', '用户名已存在');
            return res.redirect('/register');
        }

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        await User.create({
            username,
            password_hash: hash,
            role: 'superadmin'
        });

        req.flash('info', '超级管理员创建成功，请登录');
        res.redirect('/login');
    } catch (error) {
        console.error(error);
        req.flash('info', '注册失败');
        res.redirect('/register');
    }
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
