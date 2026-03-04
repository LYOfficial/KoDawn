const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const path = require('path');
const expressLayouts = require('express-ejs-layouts');
const SequelizeStore = require('connect-session-sequelize')(session.Store);

// 加载环境变量
require('dotenv').config();

// 初始化Express
const app = express();

// 数据库和模型
const { sequelize } = require('./models');

// 配置Session存储
const sessionStore = new SequelizeStore({
    db: sequelize
});

// 中间件配置
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
app.use(express.static(path.join(__dirname, 'static')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session配置
app.use(session({
    secret: process.env.SECRET_KEY || 'KoDawn-Secret-Key-Change-This',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000 // 24小时
    }
}));

// Flash消息
app.use(flash());

// Passport认证
require('./config/passport')(passport);
app.use(passport.initialize());
app.use(passport.session());

// 全局变量中间件
app.use((req, res, next) => {
    res.locals.current_user = req.user || null;
    res.locals.messages = req.flash('info');
    res.locals.errors = req.flash('error');
    next();
});

// 路由
const indexRoutes = require('./routes/index');
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const dispatcherRoutes = require('./routes/dispatcher');
const bookingRoutes = require('./routes/booking');

app.use('/', indexRoutes);
app.use('/', authRoutes);
app.use('/admin', adminRoutes);
app.use('/dispatcher', dispatcherRoutes);
app.use('/', bookingRoutes);

// 错误处理
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('error', { message: '服务器内部错误' });
});

// 404处理
app.use((req, res) => {
    res.status(404).render('error', { message: '页面未找到' });
});

// 启动服务器
const PORT = process.env.PORT || 5000;

async function startServer() {
    try {
        // 同步数据库
        await sequelize.sync();
        // 同步Session表
        await sessionStore.sync();
        
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 KoDawn 服务器运行在 http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('启动失败:', error);
        process.exit(1);
    }
}

startServer();
