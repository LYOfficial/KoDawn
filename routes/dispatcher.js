const express = require('express');
const router = express.Router();
const { ensureDispatcher } = require('../middleware/auth');
const { User, Project, Activity, Slot, Booking, DispatcherConfig, Group } = require('../models');
const { getLocalNow, formatDateTime, parseDateTime, parseDateOnly, getAppWeekdayIndex } = require('../utils/helpers');

// 放号员仪表盘
router.get('/', ensureDispatcher, async (req, res) => {
    try {
        if (req.user.role === 'superadmin') {
            req.flash('info', '超级管理员请在管理中心操作');
            return res.redirect('/admin');
        }
        const project = await Project.findByPk(req.user.project_id, {
            include: [{ model: Activity, as: 'activities' }]
        });
        
        res.render('dispatcher_dash', { project });
    } catch (error) {
        console.error(error);
        req.flash('info', '获取项目失败');
        res.redirect('/');
    }
});

// 时段管理页面
router.get('/manage/:activity_id', ensureDispatcher, async (req, res) => {
    const { activity_id } = req.params;
    
    try {
        const activity = await Activity.findByPk(activity_id, {
            include: [{ model: Project, as: 'project' }]
        });
        
        if (!activity) {
            return res.status(404).render('error', { message: '活动不存在' });
        }
        
        if (req.user.role !== 'superadmin' && activity.project.id !== req.user.project_id) {
            return res.status(403).render('error', { message: '没有权限' });
        }
        
        // 获取或创建配置
        let config = await DispatcherConfig.findOne({
            where: { activity_id, dispatcher_id: req.user.id }
        });
        
        if (!config) {
            config = await DispatcherConfig.create({
                activity_id,
                dispatcher_id: req.user.id
            });
        }
        
        // 获取我的时段
        const slots = await Slot.findAll({
            where: { activity_id, dispatcher_id: req.user.id },
            order: [['start_time', 'ASC']],
            include: [{ model: Booking, as: 'bookings' }]
        });
        
        // 处理可见字段
        const visibleKeys = activity.project.dispatcher_visible_fields
            .split(',')
            .map(k => k.trim())
            .filter(k => k);
        
        for (const slot of slots) {
            slot.data = slot.info_json ? JSON.parse(slot.info_json) : {};
            slot.booking_list_processed = [];
            
            for (const booking of slot.bookings) {
                const rawData = booking.booker_json ? JSON.parse(booking.booker_json) : {};
                const filteredData = {};
                for (const key of visibleKeys) {
                    if (rawData[key]) {
                        filteredData[key] = rawData[key];
                    }
                }
                slot.booking_list_processed.push(filteredData);
            }
        }
        
        // 准备字段列表
        const fields = activity.project.dispatcher_fields
            .split(',')
            .map(f => f.trim())
            .filter(f => f);
        
        // 准备时间选项
        let timeOptions = [];
        if (activity.project.time_mode === 'class') {
            const sections = activity.project.class_sections_json 
                ? JSON.parse(activity.project.class_sections_json) 
                : [];
            for (const sec of sections) {
                timeOptions.push({
                    label: `${sec.name} (${sec.start} - ${sec.end})`,
                    value: `${sec.start}|${sec.end}`
                });
            }
        } else if (activity.project.time_mode === 'hourly') {
            for (let h = 0; h < 24; h++) {
                const start = String(h).padStart(2, '0') + ':00';
                const end = String(h + 1).padStart(2, '0') + ':00';
                timeOptions.push({
                    label: `${start} - ${end}`,
                    value: `${start}|${end}`
                });
            }
        }
        
        res.render('slot_manage', {
            activity,
            slots,
            fields,
            timeOptions,
            config,
            formatDateTime
        });
    } catch (error) {
        console.error(error);
        req.flash('info', '获取活动失败');
        res.redirect('/dispatcher');
    }
});

// 发布时段处理
router.post('/manage/:activity_id', ensureDispatcher, async (req, res) => {
    const { activity_id } = req.params;
    const { action } = req.body;
    
    try {
        const activity = await Activity.findByPk(activity_id, {
            include: [{ model: Project, as: 'project' }]
        });
        
        if (!activity || (req.user.role !== 'superadmin' && activity.project.id !== req.user.project_id)) {
            return res.status(403).render('error', { message: '没有权限' });
        }
        
        // 更新限额配置
        if (action === 'update_limit') {
            await DispatcherConfig.update({
                enable_limit: !!req.body.enable_limit,
                max_quota: parseInt(req.body.max_quota) || 0
            }, {
                where: { activity_id, dispatcher_id: req.user.id }
            });
            
            req.flash('info', '限额配置已更新');
            return res.redirect(`/dispatcher/manage/${activity_id}`);
        }
        
        // 发布新时段
        const capacity = parseInt(req.body.capacity) || 1;
        let startDt, endDt;
        
        if (activity.project.time_mode === 'manual') {
            startDt = parseDateTime(req.body.start_time);
            endDt = parseDateTime(req.body.end_time);
        } else {
            const dateStr = req.body.select_date;
            const timeRange = req.body.time_range;
            
            if (!dateStr || !timeRange) {
                req.flash('info', '请完整选择日期和时段');
                return res.redirect(`/dispatcher/manage/${activity_id}`);
            }
            
            const selectedDate = parseDateOnly(dateStr);
            
            // 检查截止日期
            if (activity.end_date && selectedDate > parseDateOnly(activity.end_date)) {
                req.flash('info', `不能设置截止日期(${activity.end_date})之后的时间`);
                return res.redirect(`/dispatcher/manage/${activity_id}`);
            }
            
            // 检查星期
            const weekdayIndex = getAppWeekdayIndex(dateStr);
            const weekday = weekdayIndex === null ? '' : String(weekdayIndex);
            const allowedWeekdays = activity.project.allowed_weekdays.split(',');
            if (!allowedWeekdays.includes(weekday)) {
                req.flash('info', '所选日期的星期不在允许放号范围内');
                return res.redirect(`/dispatcher/manage/${activity_id}`);
            }
            
            const [startTime, endTime] = timeRange.split('|');
            startDt = parseDateTime(`${dateStr} ${startTime}`);
            endDt = parseDateTime(`${dateStr} ${endTime}`);
        }
        
        // 手动模式也检查截止日期
        if (activity.project.time_mode === 'manual' && activity.end_date) {
            if (startDt > parseDateOnly(activity.end_date)) {
                req.flash('info', `不能设置截止日期(${activity.end_date})之后的时间`);
                return res.redirect(`/dispatcher/manage/${activity_id}`);
            }
        }
        
        // 收集放号信息字段
        const fields = activity.project.dispatcher_fields.split(',').map(f => f.trim()).filter(f => f);
        const data = {};
        for (const field of fields) {
            data[field] = req.body[`field_${field}`] || '';
        }
        
        await Slot.create({
            activity_id,
            dispatcher_id: req.user.id,
            start_time: startDt,
            end_time: endDt,
            capacity,
            info_json: JSON.stringify(data)
        });
        
        req.flash('info', '发布成功');
        res.redirect(`/dispatcher/manage/${activity_id}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '发布失败');
        res.redirect(`/dispatcher/manage/${activity_id}`);
    }
});

// 删除时段
router.get('/delete_slot/:slot_id', ensureDispatcher, async (req, res) => {
    const { slot_id } = req.params;
    
    try {
        const slot = await Slot.findByPk(slot_id, {
            include: [{ model: Activity, as: 'activity', include: [{ model: Project, as: 'project' }] }]
        });
        
        if (!slot || (req.user.role !== 'superadmin' && slot.dispatcher_id !== req.user.id)) {
            return res.status(403).render('error', { message: '没有权限' });
        }
        
        if (!slot.activity.project.allow_edit) {
            req.flash('info', '管理员已锁定修改权限');
            return res.redirect(`/dispatcher/manage/${slot.activity_id}`);
        }
        
        const activityId = slot.activity_id;
        await Slot.destroy({ where: { id: slot_id } });
        
        req.flash('info', '时段已删除');
        res.redirect(`/dispatcher/manage/${activityId}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '删除失败');
        res.redirect('/dispatcher');
    }
});

module.exports = router;
