const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const { User } = require('../models');

module.exports = function(passport) {
    // 本地策略
    passport.use(new LocalStrategy(
        async (username, password, done) => {
            try {
                // 查找用户
                const user = await User.findOne({ where: { username } });
                
                if (!user) {
                    return done(null, false, { message: '用户名或密码错误' });
                }
                
                // 验证密码
                const isMatch = await bcrypt.compare(password, user.password_hash);
                
                if (!isMatch) {
                    return done(null, false, { message: '用户名或密码错误' });
                }
                
                return done(null, user);
            } catch (error) {
                return done(error);
            }
        }
    ));
    
    // 序列化用户
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });
    
    // 反序列化用户
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findByPk(id);
            done(null, user);
        } catch (error) {
            done(error);
        }
    });
};
