const { Project, Activity, Booking } = require('../models');

/**
 * 获取当前本地时间
 */
function getLocalNow() {
    const timezone = process.env.APP_TIMEZONE || 'Asia/Shanghai';
    try {
        return new Date(new Date().toLocaleString('en-US', { timeZone: timezone }));
    } catch (e) {
        return new Date();
    }
}

/**
 * 生成随机数字码
 * @param {number} length - 码的长度
 * @returns {Promise<string>} - 生成的唯一码
 */
async function generateCode(length) {
    const rangeStart = Math.pow(10, length - 1);
    const rangeEnd = Math.pow(10, length) - 1;
    
    while (true) {
        const code = String(Math.floor(Math.random() * (rangeEnd - rangeStart + 1)) + rangeStart);
        
        if (length === 6) {
            const existing = await Project.findOne({ where: { code } });
            if (!existing) return code;
        } else if (length === 8) {
            const existing = await Activity.findOne({ where: { code } });
            if (!existing) return code;
        } else if (length === 10) {
            const existing = await Booking.findOne({ where: { booking_code: code } });
            if (!existing) return code;
        } else {
            return code;
        }
    }
}

/**
 * 获取默认课节设置
 */
function getDefaultSections() {
    return [
        { name: "第一节", start: "08:00", end: "09:30" },
        { name: "第二节", start: "10:00", end: "11:30" },
        { name: "第三节", start: "13:30", end: "15:00" },
        { name: "第四节", start: "15:20", end: "16:50" },
        { name: "第五节", start: "17:10", end: "18:40" },
        { name: "第六节", start: "19:30", end: "21:00" }
    ];
}

/**
 * 格式化日期时间
 * @param {Date} date - 日期对象
 * @param {string} format - 格式化类型
 */
function formatDateTime(date, format = 'full') {
    if (!date) return '';
    const d = new Date(date);
    
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    
    switch (format) {
        case 'date':
            return `${year}-${month}-${day}`;
        case 'time':
            return `${hours}:${minutes}`;
        case 'monthday':
            return `${month}-${day}`;
        case 'datetime':
            return `${year}-${month}-${day} ${hours}:${minutes}`;
        default:
            return `${year}-${month}-${day} ${hours}:${minutes}`;
    }
}

/**
 * 解析日期时间字符串
 * @param {string} str - 日期时间字符串 (YYYY-MM-DDTHH:MM)
 */
function parseDateTime(str) {
    if (!str) return null;
    return new Date(str.replace('T', ' '));
}

/**
 * 获取星期几名称
 */
function getWeekdayNames() {
    return ['周一', '周二', '周三', '周四', '周五', '周六', '周日'];
}

module.exports = {
    getLocalNow,
    generateCode,
    getDefaultSections,
    formatDateTime,
    parseDateTime,
    getWeekdayNames
};
