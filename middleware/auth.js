// 认证中间件
const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    req.flash('error', '请先登录');
    res.redirect('/login');
};

// 管理员权限中间件
const ensureAdmin = (req, res, next) => {
    if (req.isAuthenticated() && (req.user.role === 'admin' || req.user.role === 'superadmin')) {
        return next();
    }
    res.status(403).render('error', { message: '没有权限访问此页面' });
};

// 超级管理员权限中间件
const ensureSuperAdmin = (req, res, next) => {
    if (req.isAuthenticated() && req.user.role === 'superadmin') {
        return next();
    }
    res.status(403).render('error', { message: '没有权限访问此页面' });
};

// 放号员权限中间件
const ensureDispatcher = (req, res, next) => {
    if (req.isAuthenticated() && (req.user.role === 'dispatcher' || req.user.role === 'superadmin')) {
        return next();
    }
    res.status(403).render('error', { message: '没有权限访问此页面' });
};

module.exports = {
    ensureAuthenticated,
    ensureAdmin,
    ensureSuperAdmin,
    ensureDispatcher
};
