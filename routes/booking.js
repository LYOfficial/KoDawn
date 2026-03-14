const express = require('express');
const router = express.Router();
const { Activity, Project, Slot, Booking, DispatcherConfig, User, Group } = require('../models');
const { generateCode, getLocalNow, formatDateTime, parseDateOnly } = require('../utils/helpers');

// 活动入口
router.post('/book_entry', async (req, res) => {
    const { code } = req.body;
    
    try {
        const activity = await Activity.findOne({ where: { code } });
        
        if (!activity) {
            req.flash('info', '无效的活动编号');
            return res.redirect('/');
        }
        
        res.redirect(`/book/${code}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '查询失败');
        res.redirect('/');
    }
});

// 活动时段列表
router.get('/book/:code_str', async (req, res) => {
    const { code_str } = req.params;
    
    try {
        const activity = await Activity.findOne({
            where: { code: code_str },
            include: [{ 
                model: Project, 
                as: 'project',
                include: [{ model: Group, as: 'groups' }]
            }]
        });
        
        if (!activity) {
            return res.status(404).render('error', { message: '活动不存在' });
        }
        
        const now = getLocalNow();
        let notStarted = false;
        let ended = false;
        
        // 状态判断
        if (activity.start_time && now < new Date(activity.start_time)) {
            notStarted = true;
        }
        if (activity.end_time && now > new Date(activity.end_time)) {
            ended = true;
        }
        if (activity.end_date && parseDateOnly(activity.end_date) < now) {
            ended = true;
        }
        
        // 获取所有时段
        const slots = await Slot.findAll({
            where: { activity_id: activity.id },
            order: [['start_time', 'ASC']],
            include: [{ 
                model: User, 
                as: 'dispatcher',
                include: [{ model: Group, as: 'userGroups' }]
            }]
        });
        
        // 检查每个放号员的限额状态
        const dispatcherStatus = {};
        const involvedDispatchers = new Set(slots.map(s => s.dispatcher_id));
        
        for (const did of involvedDispatchers) {
            const config = await DispatcherConfig.findOne({
                where: { activity_id: activity.id, dispatcher_id: did }
            });
            
            let totalBookings = 0;
            const dispatcherSlots = await Slot.findAll({
                where: { activity_id: activity.id, dispatcher_id: did },
                include: [{ model: Booking, as: 'bookings' }]
            });
            for (const s of dispatcherSlots) {
                totalBookings += s.bookings.length;
            }
            
            let isFull = false;
            if (config && config.enable_limit && totalBookings >= config.max_quota) {
                isFull = true;
            }
            dispatcherStatus[did] = isFull;
        }
        
        // 按小组分类
        const projectGroups = activity.project.groups;
        const groupMap = {};
        for (const g of projectGroups) {
            groupMap[g.id] = g;
        }
        
        const slotsByGroup = {};
        for (const gId in groupMap) {
            slotsByGroup[gId] = [];
        }
        const slotsUngrouped = [];
        
        for (const slot of slots) {
            slot.data = slot.info_json ? JSON.parse(slot.info_json) : {};
            slot.remain = slot.capacity - slot.current_count;
            slot.dispatcherFull = dispatcherStatus[slot.dispatcher_id] || false;
            
            slot.disabled = false;
            if (notStarted || ended) {
                slot.disabled = true;
            } else if (slot.remain <= 0 || slot.dispatcherFull) {
                slot.disabled = true;
            }
            
            slot.isTaken = (slot.remain <= 0 || slot.dispatcherFull);
            
            const dispatcher = slot.dispatcher;
            if (!dispatcher.userGroups || dispatcher.userGroups.length === 0) {
                slotsUngrouped.push(slot);
            } else {
                for (const g of dispatcher.userGroups) {
                    if (slotsByGroup[g.id]) {
                        slotsByGroup[g.id].push(slot);
                    }
                }
            }
        }
        
        // 排序函数
        const sortSlots = (slotList) => {
            return slotList.sort((a, b) => a.isTaken - b.isTaken);
        };
        
        const finalGroups = [];
        for (const g of projectGroups) {
            if (slotsByGroup[g.id] && slotsByGroup[g.id].length > 0) {
                finalGroups.push({
                    name: g.name,
                    slots: sortSlots(slotsByGroup[g.id])
                });
            }
        }
        
        if (slotsUngrouped.length > 0) {
            finalGroups.push({
                name: '其他',
                slots: sortSlots(slotsUngrouped)
            });
        }
        
        res.render('booking_list', {
            activity,
            grouped_slots: finalGroups,
            not_started: notStarted,
            ended,
            now,
            formatDateTime
        });
    } catch (error) {
        console.error(error);
        req.flash('info', '获取活动失败');
        res.redirect('/');
    }
});

// 预约表单
router.get('/book/:code_str/slot/:slot_id', async (req, res) => {
    const { code_str, slot_id } = req.params;
    
    try {
        const slot = await Slot.findByPk(slot_id, {
            include: [{ 
                model: Activity, 
                as: 'activity',
                include: [{ model: Project, as: 'project' }]
            }]
        });
        
        if (!slot) {
            return res.status(404).render('error', { message: '时段不存在' });
        }
        
        const activity = slot.activity;
        const now = getLocalNow();
        
        // 检查活动状态
        if (activity.start_time && now < new Date(activity.start_time)) {
            req.flash('info', '活动尚未开始');
            return res.redirect(`/book/${code_str}`);
        }
        if (activity.end_time && now > new Date(activity.end_time)) {
            req.flash('info', '活动已结束');
            return res.redirect(`/book/${code_str}`);
        }
        if (activity.end_date && parseDateOnly(activity.end_date) < now) {
            req.flash('info', '活动已结束');
            return res.redirect(`/book/${code_str}`);
        }
        
        // 检查名额
        if (slot.current_count >= slot.capacity) {
            req.flash('info', '该时段已约满');
            return res.redirect(`/book/${code_str}`);
        }
        
        // 检查放号员限额
        const config = await DispatcherConfig.findOne({
            where: { activity_id: activity.id, dispatcher_id: slot.dispatcher_id }
        });
        
        if (config && config.enable_limit) {
            const dispatcherSlots = await Slot.findAll({
                where: { activity_id: activity.id, dispatcher_id: slot.dispatcher_id },
                include: [{ model: Booking, as: 'bookings' }]
            });
            let totalBookings = 0;
            for (const s of dispatcherSlots) {
                totalBookings += s.bookings.length;
            }
            
            if (totalBookings >= config.max_quota) {
                req.flash('info', '该放号员接单已达上限，无法预约');
                return res.redirect(`/book/${code_str}`);
            }
        }
        
        const fields = activity.project.booker_fields
            .split(',')
            .map(f => f.trim())
            .filter(f => f);
        
        const slotInfo = slot.info_json ? JSON.parse(slot.info_json) : {};
        
        res.render('booking_form', {
            slot,
            slot_info: slotInfo,
            fields,
            activity,
            formatDateTime
        });
    } catch (error) {
        console.error(error);
        req.flash('info', '获取时段失败');
        res.redirect(`/book/${code_str}`);
    }
});

// 提交预约
router.post('/book/:code_str/slot/:slot_id', async (req, res) => {
    const { code_str, slot_id } = req.params;
    
    try {
        const slot = await Slot.findByPk(slot_id, {
            include: [{ 
                model: Activity, 
                as: 'activity',
                include: [{ model: Project, as: 'project' }]
            }]
        });
        
        if (!slot) {
            return res.status(404).render('error', { message: '时段不存在' });
        }
        
        const activity = slot.activity;
        const fields = activity.project.booker_fields
            .split(',')
            .map(f => f.trim())
            .filter(f => f);
        
        // 收集预约信息
        const data = {};
        for (const field of fields) {
            data[field] = req.body[`field_${field}`] || '';
        }
        
        const bookingCode = await generateCode(10);
        
        // 创建预约
        await Booking.create({
            slot_id: slot.id,
            booker_json: JSON.stringify(data),
            booking_code: bookingCode
        });
        
        // 更新计数
        await Slot.update(
            { current_count: slot.current_count + 1 },
            { where: { id: slot.id } }
        );
        
        res.render('success', { code: code_str, booking_code: bookingCode });
    } catch (error) {
        console.error(error);
        req.flash('info', '预约失败');
        res.redirect(`/book/${code_str}`);
    }
});

// 取号查询入口
router.get('/manage_booking_entry', (req, res) => {
    res.render('manage_booking_entry');
});

router.post('/manage_booking_entry', async (req, res) => {
    const { booking_code } = req.body;
    
    try {
        const booking = await Booking.findOne({ where: { booking_code } });
        
        if (booking) {
            res.redirect(`/manage_booking/view/${booking_code}`);
        } else {
            req.flash('info', '未找到该取号码');
            res.redirect('/manage_booking_entry');
        }
    } catch (error) {
        console.error(error);
        req.flash('info', '查询失败');
        res.redirect('/manage_booking_entry');
    }
});

// 查看预约详情
router.get('/manage_booking/view/:b_code', async (req, res) => {
    const { b_code } = req.params;
    
    try {
        const booking = await Booking.findOne({
            where: { booking_code: b_code },
            include: [{
                model: Slot,
                as: 'slot',
                include: [{
                    model: Activity,
                    as: 'activity',
                    include: [{ model: Project, as: 'project' }]
                }]
            }]
        });
        
        if (!booking) {
            return res.status(404).render('error', { message: '预约不存在' });
        }
        
        booking.data = booking.booker_json ? JSON.parse(booking.booker_json) : {};
        booking.slot.data = booking.slot.info_json ? JSON.parse(booking.slot.info_json) : {};
        
        res.render('manage_booking_view', { 
            booking,
            formatDateTime
        });
    } catch (error) {
        console.error(error);
        req.flash('info', '获取预约失败');
        res.redirect('/manage_booking_entry');
    }
});

// 删除预约
router.post('/manage_booking/delete/:b_code', async (req, res) => {
    const { b_code } = req.params;
    
    try {
        const booking = await Booking.findOne({
            where: { booking_code: b_code },
            include: [{ model: Slot, as: 'slot' }]
        });
        
        if (!booking) {
            return res.status(404).render('error', { message: '预约不存在' });
        }
        
        const slot = booking.slot;
        
        // 更新计数
        let newCount = slot.current_count - 1;
        if (newCount < 0) newCount = 0;
        
        await Slot.update(
            { current_count: newCount },
            { where: { id: slot.id } }
        );
        
        await Booking.destroy({ where: { id: booking.id } });
        
        req.flash('info', '取号已删除（取消预约）');
        res.redirect('/');
    } catch (error) {
        console.error(error);
        req.flash('info', '删除失败');
        res.redirect('/manage_booking_entry');
    }
});

module.exports = router;
