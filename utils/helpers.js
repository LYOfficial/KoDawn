const { Project, Activity, Booking } = require('../models');

const DEFAULT_TIMEZONE = process.env.APP_TIMEZONE || 'Asia/Shanghai';
let cachedTimezone = DEFAULT_TIMEZONE;

function getAppTimezone() {
    return cachedTimezone || DEFAULT_TIMEZONE;
}

function setAppTimezone(timezone) {
    if (timezone) {
        cachedTimezone = timezone;
    }
}

async function loadAppTimezone() {
    try {
        const { AppConfig } = require('../models');
        const record = await AppConfig.findOne({ where: { key: 'timezone' } });
        if (record && record.value) {
            cachedTimezone = record.value;
        }
    } catch (e) {
        // ignore loading errors and keep default
    }
    return getAppTimezone();
}

function getTimeZoneOffsetMinutes(date, timeZone) {
    const dtf = new Intl.DateTimeFormat('en-US', {
        timeZone,
        hour12: false,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    const parts = dtf.formatToParts(date);
    const values = {};
    for (const part of parts) {
        if (part.type !== 'literal') {
            values[part.type] = part.value;
        }
    }
    const asUTC = Date.UTC(
        parseInt(values.year, 10),
        parseInt(values.month, 10) - 1,
        parseInt(values.day, 10),
        parseInt(values.hour, 10),
        parseInt(values.minute, 10),
        parseInt(values.second, 10)
    );
    return (asUTC - date.getTime()) / 60000;
}

function getZonedParts(date, timeZone) {
    const dtf = new Intl.DateTimeFormat('en-US', {
        timeZone,
        hour12: false,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
    const parts = dtf.formatToParts(date);
    const values = {};
    for (const part of parts) {
        if (part.type !== 'literal') {
            values[part.type] = part.value;
        }
    }
    return values;
}

/**
 * 获取当前本地时间
 */
function getLocalNow() {
    return new Date();
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
    const timezone = getAppTimezone();
    const parts = getZonedParts(d, timezone);
    const year = parts.year;
    const month = parts.month;
    const day = parts.day;
    const hours = parts.hour;
    const minutes = parts.minute;
    
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
    const timezone = getAppTimezone();
    const normalized = str.replace('T', ' ').trim();
    const [datePart, timePart] = normalized.split(' ');
    if (!datePart) return null;
    const [year, month, day] = datePart.split('-').map((n) => parseInt(n, 10));
    const [hour = 0, minute = 0] = (timePart || '00:00').split(':').map((n) => parseInt(n, 10));

    const utcDate = new Date(Date.UTC(year, month - 1, day, hour, minute, 0));
    const offset = getTimeZoneOffsetMinutes(utcDate, timezone);
    return new Date(utcDate.getTime() - offset * 60000);
}

function parseDateOnly(dateStr) {
    if (!dateStr) return null;
    return parseDateTime(`${dateStr} 00:00`);
}

function getAppWeekdayIndex(dateStr) {
    if (!dateStr) return null;
    const timezone = getAppTimezone();
    const [year, month, day] = dateStr.split('-').map((n) => parseInt(n, 10));
    const probe = new Date(Date.UTC(year, month - 1, day, 12, 0, 0));
    const weekdayName = new Intl.DateTimeFormat('en-US', {
        timeZone: timezone,
        weekday: 'short'
    }).format(probe);
    const map = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
    if (weekdayName in map) {
        const jsIndex = map[weekdayName];
        return jsIndex === 0 ? 6 : jsIndex - 1;
    }
    return null;
}

/**
 * 获取星期几名称
 */
function getWeekdayNames() {
    return ['周一', '周二', '周三', '周四', '周五', '周六', '周日'];
}

module.exports = {
    getLocalNow,
    getAppTimezone,
    setAppTimezone,
    loadAppTimezone,
    generateCode,
    getDefaultSections,
    formatDateTime,
    parseDateTime,
    parseDateOnly,
    getAppWeekdayIndex,
    getWeekdayNames
};
