const path = require('path');
const fs = require('fs');

// 确保数据目录存在
const dataDir = path.join(__dirname, '..', 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

const { sequelize, Booking } = require('../models');
const { generateCode } = require('../utils/helpers');

async function updateDb() {
    console.log('开始检查数据库结构...');
    
    try {
        // 同步所有表
        await sequelize.sync({ alter: true });
        console.log('√ 基础表结构检查完成');
        
        // 检查旧数据完整性
        console.log('检查旧数据完整性...');
        
        const bookingsWithoutCode = await Booking.findAll({
            where: { booking_code: null }
        });
        
        if (bookingsWithoutCode.length > 0) {
            console.log(`  > 发现 ${bookingsWithoutCode.length} 个旧预约缺失取号码，正在生成...`);
            let count = 0;
            
            for (const b of bookingsWithoutCode) {
                const code = await generateCode(10);
                await Booking.update(
                    { booking_code: code },
                    { where: { id: b.id } }
                );
                count++;
            }
            
            console.log(`  √ 已修复 ${count} 条数据`);
        }
        
        console.log('\n恭喜！数据库升级完成，你可以正常启动网站了。');
        process.exit(0);
    } catch (error) {
        console.error('升级失败:', error);
        process.exit(1);
    }
}

updateDb();
