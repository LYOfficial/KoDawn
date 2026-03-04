const readline = require('readline');
const bcrypt = require('bcryptjs');
const path = require('path');

// 确保数据目录存在
const fs = require('fs');
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const { sequelize, User } = require('../models');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function createAdmin() {
    try {
        await sequelize.sync();
        
        rl.question('请输入管理员用户名: ', async (username) => {
            rl.question('请输入管理员密码: ', async (password) => {
                try {
                    // 检查用户名是否存在
                    const existing = await User.findOne({ where: { username } });
                    if (existing) {
                        console.log('错误：该用户名已存在。');
                        rl.close();
                        process.exit(1);
                    }
                    
                    // 创建管理员
                    const salt = await bcrypt.genSalt(10);
                    const hash = await bcrypt.hash(password, salt);
                    
                    await User.create({
                        username,
                        password_hash: hash,
                        role: 'admin'
                    });
                    
                    console.log(`管理员 ${username} 创建成功！`);
                    rl.close();
                    process.exit(0);
                } catch (error) {
                    console.error('创建失败:', error);
                    rl.close();
                    process.exit(1);
                }
            });
        });
    } catch (error) {
        console.error('数据库连接失败:', error);
        process.exit(1);
    }
}

createAdmin();
