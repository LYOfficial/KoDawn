const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { ensureAdmin, ensureSuperAdmin } = require('../middleware/auth');
const { sequelize, User, Project, Group, Activity, Slot, Booking, DispatcherConfig, AdminProjects, DispatcherGroups, AppConfig } = require('../models');
const { generateCode, getDefaultSections, formatDateTime, formatDateTimeInput, parseDateTime, getAppTimezone, setAppTimezone } = require('../utils/helpers');

// 管理员仪表盘
router.get('/', ensureAdmin, async (req, res) => {
    try {
        const isSuperAdmin = req.user.role === 'superadmin';
        let appTimezone = getAppTimezone();
        if (isSuperAdmin) {
            const config = await AppConfig.findOne({ where: { key: 'timezone' } });
            if (config && config.value) {
                appTimezone = config.value;
            }
        }
        const projects = isSuperAdmin
            ? await Project.findAll({ order: [['id', 'ASC']] })
            : await req.user.getManaged_projects();
        const users = isSuperAdmin
            ? await User.findAll({ include: [{ model: Project, as: 'project' }], order: [['id', 'ASC']] })
            : [];
        const admins = isSuperAdmin
            ? await User.findAll({ where: { role: 'admin' }, order: [['id', 'ASC']] })
            : [];
        res.render('admin_dash', { projects, is_superadmin: isSuperAdmin, users, admins, app_timezone: appTimezone });
    } catch (error) {
        console.error(error);
        req.flash('info', '获取项目列表失败');
        res.redirect('/');
    }
});

// 超级管理员更新平台时区
router.post('/update_timezone', ensureSuperAdmin, async (req, res) => {
    const { timezone } = req.body;
    if (!timezone) {
        req.flash('info', '时区不能为空');
        return res.redirect('/admin');
    }

    try {
        try {
            new Intl.DateTimeFormat('en-US', { timeZone: timezone });
        } catch (e) {
            req.flash('info', '无效的时区标识，请使用 IANA 格式');
            return res.redirect('/admin');
        }

        const existing = await AppConfig.findOne({ where: { key: 'timezone' } });
        if (existing) {
            await AppConfig.update({ value: timezone }, { where: { key: 'timezone' } });
        } else {
            await AppConfig.create({ key: 'timezone', value: timezone });
        }
        setAppTimezone(timezone);

        req.flash('info', '平台时区已更新');
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '更新时区失败');
        res.redirect('/admin');
    }
});

// 超级管理员创建管理员
router.post('/create_admin', ensureSuperAdmin, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        req.flash('info', '用户名和密码不能为空');
        return res.redirect('/admin');
    }

    try {
        const existing = await User.findOne({ where: { username } });
        if (existing) {
            req.flash('info', '用户名已存在');
            return res.redirect('/admin');
        }

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        await User.create({
            username,
            password_hash: hash,
            role: 'admin'
        });

        req.flash('info', `管理员 ${username} 创建成功`);
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '创建失败');
        res.redirect('/admin');
    }
});

// 超级管理员执行数据库升级
router.post('/update_db', ensureSuperAdmin, async (req, res) => {
    try {
        await sequelize.sync({ alter: true });

        const bookingsWithoutCode = await Booking.findAll({
            where: { booking_code: null }
        });

        for (const b of bookingsWithoutCode) {
            const code = await generateCode(10);
            await Booking.update(
                { booking_code: code },
                { where: { id: b.id } }
            );
        }

        req.flash('info', '数据库升级完成');
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '数据库升级失败');
        res.redirect('/admin');
    }
});

// 超级管理员更新用户
router.post('/update_user', ensureSuperAdmin, async (req, res) => {
    const { user_id, role, project_id } = req.body;
    if (!user_id) {
        req.flash('info', '用户不存在');
        return res.redirect('/admin');
    }

    try {
        const target = await User.findByPk(user_id);
        if (!target) {
            req.flash('info', '用户不存在');
            return res.redirect('/admin');
        }

        if (String(target.id) === String(req.user.id) && role && role !== 'superadmin') {
            req.flash('info', '不能降级当前登录的超级管理员');
            return res.redirect('/admin');
        }

        const updateData = {};
        const newRole = role || target.role;
        const projectIdValue = project_id ? parseInt(project_id, 10) : null;

        if (newRole === 'dispatcher') {
            if (!projectIdValue || Number.isNaN(projectIdValue)) {
                req.flash('info', '放号员必须选择项目');
                return res.redirect('/admin');
            }
            updateData.project_id = projectIdValue;
            await AdminProjects.destroy({ where: { user_id: target.id } });
        } else {
            updateData.project_id = null;
            await DispatcherGroups.destroy({ where: { user_id: target.id } });
        }

        if (role) {
            updateData.role = role;
            if (role !== 'admin') {
                await AdminProjects.destroy({ where: { user_id: target.id } });
            }
        }

        await User.update(updateData, { where: { id: target.id } });
        req.flash('info', '用户已更新');
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '更新失败');
        res.redirect('/admin');
    }
});

// 超级管理员重置用户密码
router.post('/reset_user_password', ensureSuperAdmin, async (req, res) => {
    const { user_id, new_password } = req.body;
    if (!user_id || !new_password) {
        req.flash('info', '用户和新密码不能为空');
        return res.redirect('/admin');
    }

    try {
        const target = await User.findByPk(user_id);
        if (!target) {
            req.flash('info', '用户不存在');
            return res.redirect('/admin');
        }

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(new_password, salt);
        await User.update({ password_hash: hash }, { where: { id: target.id } });

        req.flash('info', '密码已重置');
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '重置失败');
        res.redirect('/admin');
    }
});

// 超级管理员删除用户
router.post('/delete_user', ensureSuperAdmin, async (req, res) => {
    const { user_id } = req.body;
    if (!user_id) {
        req.flash('info', '用户不存在');
        return res.redirect('/admin');
    }

    try {
        const target = await User.findByPk(user_id);
        if (!target) {
            req.flash('info', '用户不存在');
            return res.redirect('/admin');
        }

        if (String(target.id) === String(req.user.id)) {
            req.flash('info', '不能删除当前登录用户');
            return res.redirect('/admin');
        }

        await AdminProjects.destroy({ where: { user_id: target.id } });
        await DispatcherGroups.destroy({ where: { user_id: target.id } });
        await DispatcherConfig.destroy({ where: { dispatcher_id: target.id } });
        await Slot.destroy({ where: { dispatcher_id: target.id } });
        await User.destroy({ where: { id: target.id } });

        req.flash('info', '用户已删除');
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '删除失败');
        res.redirect('/admin');
    }
});

// 超级管理员分配项目给管理员
router.post('/assign_admin_project', ensureSuperAdmin, async (req, res) => {
    const { admin_id, project_id } = req.body;
    if (!admin_id || !project_id) {
        req.flash('info', '请选择管理员和项目');
        return res.redirect('/admin');
    }

    try {
        const adminUser = await User.findByPk(admin_id);
        const project = await Project.findByPk(project_id);

        if (!adminUser || adminUser.role !== 'admin') {
            req.flash('info', '管理员不存在');
            return res.redirect('/admin');
        }
        if (!project) {
            req.flash('info', '项目不存在');
            return res.redirect('/admin');
        }

        const existing = await AdminProjects.findOne({
            where: { user_id: adminUser.id, project_id: project.id }
        });
        if (!existing) {
            await AdminProjects.create({
                user_id: adminUser.id,
                project_id: project.id
            });
        }

        req.flash('info', '管理员已绑定项目');
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '绑定失败');
        res.redirect('/admin');
    }
});

// 超级管理员创建放号员
router.post('/create_dispatcher_global', ensureSuperAdmin, async (req, res) => {
    const { username, password, project_id } = req.body;
    if (!username || !password || !project_id) {
        req.flash('info', '用户名、密码和项目不能为空');
        return res.redirect('/admin');
    }

    try {
        const project = await Project.findByPk(project_id);
        if (!project) {
            req.flash('info', '项目不存在');
            return res.redirect('/admin');
        }

        const existing = await User.findOne({ where: { username } });
        if (existing) {
            req.flash('info', '用户名已存在');
            return res.redirect('/admin');
        }

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        await User.create({
            username,
            password_hash: hash,
            role: 'dispatcher',
            project_id: project.id
        });

        req.flash('info', '放号员创建成功');
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '创建失败');
        res.redirect('/admin');
    }
});

// 通过项目码添加项目
router.post('/add_project_by_code', ensureAdmin, async (req, res) => {
    const { project_code } = req.body;
    
    if (!project_code) {
        req.flash('info', '请输入项目码');
        return res.redirect('/admin');
    }
    
    try {
        const project = await Project.findOne({ where: { code: project_code } });
        
        if (!project) {
            req.flash('info', '未找到该项目码对应的项目');
            return res.redirect('/admin');
        }
        
        // 检查是否已经管理
        const existing = await AdminProjects.findOne({
            where: { user_id: req.user.id, project_id: project.id }
        });
        
        if (existing) {
            req.flash('info', '你已经管理该项目了');
        } else {
            await AdminProjects.create({
                user_id: req.user.id,
                project_id: project.id
            });
            req.flash('info', `成功添加项目：${project.name}`);
        }
        
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '添加失败');
        res.redirect('/admin');
    }
});

// 创建项目
router.post('/create_project', ensureAdmin, async (req, res) => {
    const { name } = req.body;
    
    if (!name) {
        req.flash('info', '请输入项目名称');
        return res.redirect('/admin');
    }
    
    try {
        const code = await generateCode(6);
        const sections = getDefaultSections();
        
        const project = await Project.create({
            name,
            code,
            class_sections_json: JSON.stringify(sections)
        });
        
        // 创建者自动成为管理员
        await AdminProjects.create({
            user_id: req.user.id,
            project_id: project.id
        });
        
        req.flash('info', `项目创建成功，编号：${code}`);
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '创建失败');
        res.redirect('/admin');
    }
});

// 删除项目
router.get('/delete_project/:project_id', ensureAdmin, async (req, res) => {
    const { project_id } = req.params;
    
    try {
        const isSuperAdmin = req.user.role === 'superadmin';
        // 检查权限
        const adminProject = await AdminProjects.findOne({
            where: { user_id: req.user.id, project_id }
        });
        
        if (!adminProject && !isSuperAdmin) {
            return res.status(403).render('error', { message: '没有权限' });
        }
        
        await Project.destroy({ where: { id: project_id } });
        req.flash('info', '项目已删除');
        res.redirect('/admin');
    } catch (error) {
        console.error(error);
        req.flash('info', '删除失败');
        res.redirect('/admin');
    }
});

// 项目编辑页面
router.get('/project/:project_id', ensureAdmin, async (req, res) => {
    const { project_id } = req.params;
    
    try {
        const isSuperAdmin = req.user.role === 'superadmin';
        // 检查权限
        const adminProject = await AdminProjects.findOne({
            where: { user_id: req.user.id, project_id }
        });
        
        if (!adminProject && !isSuperAdmin) {
            return res.status(403).render('error', { message: '没有权限' });
        }
        
        const project = await Project.findByPk(project_id, {
            include: [
                { model: Activity, as: 'activities' },
                { model: Group, as: 'groups' },
                { model: User, as: 'dispatchers', include: [{ model: Group, as: 'userGroups' }] }
            ]
        });
        
        if (!project) {
            return res.status(404).render('error', { message: '项目不存在' });
        }
        
        const sections = project.class_sections_json ? JSON.parse(project.class_sections_json) : getDefaultSections();
        const allowed_wd = project.allowed_weekdays ? project.allowed_weekdays.split(',') : [];
        
        res.render('project_edit', { 
            project, 
            sections, 
            allowed_wd,
            is_superadmin: isSuperAdmin,
            formatDateTime,
            formatDateTimeInput
        });
    } catch (error) {
        console.error(error);
        req.flash('info', '获取项目失败');
        res.redirect('/admin');
    }
});

// 项目编辑处理
router.post('/project/:project_id', ensureAdmin, async (req, res) => {
    const { project_id } = req.params;
    const { action } = req.body;
    
    try {
        const isSuperAdmin = req.user.role === 'superadmin';
        // 检查权限
        const adminProject = await AdminProjects.findOne({
            where: { user_id: req.user.id, project_id }
        });
        
        if (!adminProject && !isSuperAdmin) {
            return res.status(403).render('error', { message: '没有权限' });
        }
        
        const project = await Project.findByPk(project_id);
        if (!project) {
            return res.status(404).render('error', { message: '项目不存在' });
        }
        
        if (action === 'update_config') {
            const updateData = {
                dispatcher_label: req.body.dispatcher_label || '放号员',
                booker_label: req.body.booker_label || '取号员',
                dispatcher_fields: req.body.dispatcher_fields,
                booker_fields: req.body.booker_fields,
                dispatcher_visible_fields: req.body.dispatcher_visible_fields,
                allow_edit: !!req.body.allow_edit,
                time_mode: req.body.time_mode
            };
            
            // 处理允许的星期，避免表单未提交时覆盖为"空"
            const weekdays = req.body.allowed_weekdays;
            if (Array.isArray(weekdays)) {
                updateData.allowed_weekdays = weekdays.join(',');
            } else if (typeof weekdays === 'string' && weekdays) {
                updateData.allowed_weekdays = weekdays;
            } else if (typeof weekdays !== 'undefined') {
                updateData.allowed_weekdays = '';
            }
            
            // 课节模式下处理课节设置
            if (req.body.time_mode === 'class') {
                const secNames = req.body['sec_name[]'] || [];
                const secStarts = req.body['sec_start[]'] || [];
                const secEnds = req.body['sec_end[]'] || [];
                
                const newSections = [];
                const names = Array.isArray(secNames) ? secNames : [secNames];
                const starts = Array.isArray(secStarts) ? secStarts : [secStarts];
                const ends = Array.isArray(secEnds) ? secEnds : [secEnds];
                
                for (let i = 0; i < names.length; i++) {
                    if (names[i] && starts[i] && ends[i]) {
                        newSections.push({
                            name: names[i],
                            start: starts[i],
                            end: ends[i]
                        });
                    }
                }
                if (newSections.length > 0) {
                    updateData.class_sections_json = JSON.stringify(newSections);
                } else if (project.class_sections_json) {
                    updateData.class_sections_json = project.class_sections_json;
                } else {
                    updateData.class_sections_json = JSON.stringify(getDefaultSections());
                }
            }
            
            await Project.update(updateData, { where: { id: project_id } });
            req.flash('info', '设置已保存');
        }
        else if (action === 'create_dispatcher') {
            const { username, password } = req.body;
            let groupIds = req.body.groups || [];
            if (!Array.isArray(groupIds)) groupIds = [groupIds];
            
            // 检查用户名是否存在
            const existingUser = await User.findOne({ where: { username } });
            if (existingUser) {
                req.flash('info', '用户名已存在');
            } else {
                const salt = await bcrypt.genSalt(10);
                const hash = await bcrypt.hash(password, salt);
                
                const user = await User.create({
                    username,
                    password_hash: hash,
                    role: 'dispatcher',
                    project_id: project.id
                });
                
                // 添加到小组
                for (const gid of groupIds) {
                    const group = await Group.findByPk(parseInt(gid));
                    if (group && group.project_id === project.id) {
                        await DispatcherGroups.create({
                            user_id: user.id,
                            group_id: group.id
                        });
                    }
                }
                
                req.flash('info', '人员添加成功');
            }
        }
        else if (action === 'create_group') {
            const { group_name } = req.body;
            if (group_name) {
                await Group.create({
                    name: group_name,
                    project_id: project.id
                });
                req.flash('info', '小组创建成功');
            }
        }
        else if (action === 'create_activity') {
            const { name, start_time, end_time } = req.body;
            const code = await generateCode(8);
            
            await Activity.create({
                name,
                code,
                project_id: project.id,
                start_time: start_time ? parseDateTime(start_time) : null,
                end_time: end_time ? parseDateTime(end_time) : null
            });
            
            req.flash('info', `活动创建成功，编号：${code}`);
        }
        else if (action === 'update_activity') {
            const { activity_id, name, start_time, end_time } = req.body;
            if (!activity_id) {
                req.flash('info', '活动不存在');
                return res.redirect(`/admin/project/${project_id}`);
            }

            const activity = await Activity.findOne({
                where: { id: activity_id, project_id: project.id }
            });

            if (!activity) {
                req.flash('info', '活动不存在');
                return res.redirect(`/admin/project/${project_id}`);
            }

            await Activity.update({
                name: name || activity.name,
                start_time: start_time ? parseDateTime(start_time) : null,
                end_time: end_time ? parseDateTime(end_time) : null
            }, { where: { id: activity.id } });

            req.flash('info', '活动已更新');
        }
        else if (action === 'update_activity_offset') {
            if (req.user.role !== 'superadmin') {
                req.flash('info', '只有超级管理员可以进行批量时间校准');
                return res.redirect(`/admin/project/${project_id}`);
            }
            const { activity_id, offset_hours } = req.body;
            const offsetHours = parseFloat(offset_hours);

            if (!activity_id) {
                req.flash('info', '活动不存在');
                return res.redirect(`/admin/project/${project_id}`);
            }

            if (Number.isNaN(offsetHours) || offsetHours === 0) {
                req.flash('info', '请输入非零的小时偏移量');
                return res.redirect(`/admin/project/${project_id}`);
            }

            const activity = await Activity.findOne({
                where: { id: activity_id, project_id: project.id }
            });

            if (!activity) {
                req.flash('info', '活动不存在');
                return res.redirect(`/admin/project/${project_id}`);
            }

            const offsetMs = offsetHours * 60 * 60 * 1000;

            await sequelize.transaction(async (t) => {
                const updatedActivity = {};
                if (activity.start_time) {
                    updatedActivity.start_time = new Date(new Date(activity.start_time).getTime() + offsetMs);
                }
                if (activity.end_time) {
                    updatedActivity.end_time = new Date(new Date(activity.end_time).getTime() + offsetMs);
                }
                if (Object.keys(updatedActivity).length > 0) {
                    await Activity.update(updatedActivity, { where: { id: activity.id }, transaction: t });
                }

                const slots = await Slot.findAll({
                    where: { activity_id: activity.id },
                    transaction: t
                });

                for (const slot of slots) {
                    const slotUpdate = {
                        start_time: new Date(new Date(slot.start_time).getTime() + offsetMs),
                        end_time: new Date(new Date(slot.end_time).getTime() + offsetMs)
                    };
                    await Slot.update(slotUpdate, { where: { id: slot.id }, transaction: t });
                }
            });

            req.flash('info', '活动与号源时间已批量偏移');
        }
        else if (action === 'delete_project') {
            await Project.destroy({ where: { id: project_id } });
            req.flash('info', '项目已删除');
            return res.redirect('/admin');
        }
        
        res.redirect(`/admin/project/${project_id}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '操作失败');
        res.redirect(`/admin/project/${project_id}`);
    }
});

// 删除放号员
router.get('/delete_dispatcher/:dispatcher_id', ensureAdmin, async (req, res) => {
    const { dispatcher_id } = req.params;
    
    try {
        const user = await User.findByPk(dispatcher_id);
        
        if (!user || user.role !== 'dispatcher') {
            req.flash('info', '只能删除放号员');
            return res.redirect('/admin');
        }
        
        const pid = user.project_id;
        await User.destroy({ where: { id: dispatcher_id } });
        
        req.flash('info', '放号员已删除');
        res.redirect(`/admin/project/${pid}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '删除失败');
        res.redirect('/admin');
    }
});

// 删除小组
router.get('/delete_group/:group_id', ensureAdmin, async (req, res) => {
    const { group_id } = req.params;
    
    try {
        const group = await Group.findByPk(group_id);
        if (!group) {
            return res.redirect('/admin');
        }
        
        const pid = group.project_id;
        await Group.destroy({ where: { id: group_id } });
        
        req.flash('info', '小组已删除');
        res.redirect(`/admin/project/${pid}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '删除失败');
        res.redirect('/admin');
    }
});

// 重命名小组
router.post('/rename_group/:group_id', ensureAdmin, async (req, res) => {
    const { group_id } = req.params;
    const { name } = req.body;
    
    try {
        const group = await Group.findByPk(group_id);
        if (!group) {
            return res.redirect('/admin');
        }
        
        if (name) {
            await Group.update({ name }, { where: { id: group_id } });
            req.flash('info', '小组重命名成功');
        }
        
        res.redirect(`/admin/project/${group.project_id}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '重命名失败');
        res.redirect('/admin');
    }
});

// 编辑放号员页面
router.get('/edit_dispatcher/:dispatcher_id', ensureAdmin, async (req, res) => {
    const { dispatcher_id } = req.params;
    
    try {
        const user = await User.findByPk(dispatcher_id, {
            include: [{ model: Group, as: 'userGroups' }]
        });
        
        if (!user || user.role !== 'dispatcher') {
            return res.status(403).render('error', { message: '没有权限' });
        }
        
        const project = await Project.findByPk(user.project_id, {
            include: [{ model: Group, as: 'groups' }]
        });
        
        res.render('dispatcher_edit', { user, project });
    } catch (error) {
        console.error(error);
        res.redirect('/admin');
    }
});

// 编辑放号员处理
router.post('/edit_dispatcher/:dispatcher_id', ensureAdmin, async (req, res) => {
    const { dispatcher_id } = req.params;
    const { password } = req.body;
    let groupIds = req.body.groups || [];
    if (!Array.isArray(groupIds)) groupIds = [groupIds];
    
    try {
        const user = await User.findByPk(dispatcher_id);
        
        if (!user || user.role !== 'dispatcher') {
            return res.status(403).render('error', { message: '没有权限' });
        }
        
        // 更新密码
        if (password) {
            const salt = await bcrypt.genSalt(10);
            const hash = await bcrypt.hash(password, salt);
            await User.update({ password_hash: hash }, { where: { id: dispatcher_id } });
            req.flash('info', '密码已修改');
        }
        
        // 更新小组
        await DispatcherGroups.destroy({ where: { user_id: dispatcher_id } });
        for (const gid of groupIds) {
            const group = await Group.findByPk(parseInt(gid));
            if (group && group.project_id === user.project_id) {
                await DispatcherGroups.create({
                    user_id: user.id,
                    group_id: group.id
                });
            }
        }
        
        req.flash('info', '放号员信息已更新');
        res.redirect(`/admin/project/${user.project_id}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '更新失败');
        res.redirect('/admin');
    }
});

// 删除活动
router.get('/delete_activity/:activity_id', ensureAdmin, async (req, res) => {
    const { activity_id } = req.params;
    
    try {
        const activity = await Activity.findByPk(activity_id);
        if (!activity) {
            return res.redirect('/admin');
        }
        
        const pid = activity.project_id;
        await Activity.destroy({ where: { id: activity_id } });
        
        req.flash('info', '活动已删除');
        res.redirect(`/admin/project/${pid}`);
    } catch (error) {
        console.error(error);
        req.flash('info', '删除失败');
        res.redirect('/admin');
    }
});

// 活动数据详情
router.get('/activity/:activity_id', ensureAdmin, async (req, res) => {
    const { activity_id } = req.params;
    
    try {
        const activity = await Activity.findByPk(activity_id, {
            include: [{ model: Project, as: 'project' }]
        });
        
        if (!activity) {
            return res.status(404).render('error', { message: '活动不存在' });
        }
        
        const slots = await Slot.findAll({
            where: { activity_id },
            order: [['start_time', 'ASC']],
            include: [
                { model: User, as: 'dispatcher' },
                { model: Booking, as: 'bookings' }
            ]
        });
        
        // 处理数据
        for (const slot of slots) {
            slot.data = slot.info_json ? JSON.parse(slot.info_json) : {};
            for (const booking of slot.bookings) {
                booking.data = booking.booker_json ? JSON.parse(booking.booker_json) : {};
            }
        }
        
        res.render('admin_activity_detail', { 
            activity, 
            slots,
            formatDateTime
        });
    } catch (error) {
        console.error(error);
        req.flash('info', '获取数据失败');
        res.redirect('/admin');
    }
});

module.exports = router;
