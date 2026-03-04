const path = require('path');
const fs = require('fs');

// 确保数据目录存在
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const { sequelize, User } = require('../models');

async function listUsers() {
    try {
        await sequelize.sync();
        
        const users = await User.findAll();
        
        console.log('ID'.padEnd(5) + ' | ' + '用户名'.padEnd(20) + ' | ' + '角色'.padEnd(10) + ' | 项目ID');
        console.log('-'.repeat(60));
        
        for (const u of users) {
            const roleName = u.role === 'admin' ? '项目管理员' : '放号员';
            const pid = u.project_id ? u.project_id : 'N/A';
            console.log(
                String(u.id).padEnd(5) + ' | ' + 
                u.username.padEnd(20) + ' | ' + 
                roleName.padEnd(10) + ' | ' + 
                pid
            );
        }
        
        process.exit(0);
    } catch (error) {
        console.error('查询失败:', error);
        process.exit(1);
    }
}

listUsers();
