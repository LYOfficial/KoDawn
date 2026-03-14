const { Sequelize, DataTypes } = require('sequelize');
const path = require('path');

// 初始化Sequelize
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: path.join(__dirname, '..', 'data', 'kodawn.db'),
    logging: false
});

// 定义User模型
const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING(80),
        allowNull: false,
        unique: true
    },
    password_hash: {
        type: DataTypes.STRING(128)
    },
    role: {
        type: DataTypes.STRING(20)
    },
    project_id: {
        type: DataTypes.INTEGER,
        allowNull: true
    }
}, {
    tableName: 'users',
    timestamps: false
});

// 定义Project模型
const Project = sequelize.define('Project', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    code: {
        type: DataTypes.STRING(6),
        allowNull: false,
        unique: true
    },
    name: {
        type: DataTypes.STRING(100),
        allowNull: false
    },
    dispatcher_label: {
        type: DataTypes.STRING(50),
        defaultValue: '放号员'
    },
    booker_label: {
        type: DataTypes.STRING(50),
        defaultValue: '取号员'
    },
    dispatcher_fields: {
        type: DataTypes.STRING(500),
        defaultValue: '诊室,详情'
    },
    booker_fields: {
        type: DataTypes.STRING(500),
        defaultValue: '姓名,电话'
    },
    dispatcher_visible_fields: {
        type: DataTypes.STRING(500),
        defaultValue: '姓名'
    },
    time_mode: {
        type: DataTypes.STRING(20),
        defaultValue: 'manual'
    },
    allowed_weekdays: {
        type: DataTypes.STRING(50),
        defaultValue: '0,1,2,3,4,5,6'
    },
    class_sections_json: {
        type: DataTypes.TEXT,
        defaultValue: ''
    },
    allow_edit: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
    }
}, {
    tableName: 'projects',
    timestamps: false
});

// 定义Group模型
const Group = sequelize.define('Group', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    name: {
        type: DataTypes.STRING(50),
        allowNull: false
    },
    project_id: {
        type: DataTypes.INTEGER,
        allowNull: false
    }
}, {
    tableName: 'groups',
    timestamps: false
});

// 定义Activity模型
const Activity = sequelize.define('Activity', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    code: {
        type: DataTypes.STRING(8),
        allowNull: false,
        unique: true
    },
    name: {
        type: DataTypes.STRING(100),
        allowNull: false
    },
    project_id: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    end_date: {
        type: DataTypes.DATEONLY,
        allowNull: true
    },
    start_time: {
        type: DataTypes.DATE,
        allowNull: true
    },
    end_time: {
        type: DataTypes.DATE,
        allowNull: true
    }
}, {
    tableName: 'activities',
    timestamps: false
});

// 定义DispatcherConfig模型
const DispatcherConfig = sequelize.define('DispatcherConfig', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    activity_id: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    dispatcher_id: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    enable_limit: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    max_quota: {
        type: DataTypes.INTEGER,
        defaultValue: 0
    }
}, {
    tableName: 'dispatcher_configs',
    timestamps: false
});

// 定义Slot模型
const Slot = sequelize.define('Slot', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    activity_id: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    dispatcher_id: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    start_time: {
        type: DataTypes.DATE,
        allowNull: false
    },
    end_time: {
        type: DataTypes.DATE,
        allowNull: false
    },
    capacity: {
        type: DataTypes.INTEGER,
        defaultValue: 1
    },
    current_count: {
        type: DataTypes.INTEGER,
        defaultValue: 0
    },
    info_json: {
        type: DataTypes.TEXT
    }
}, {
    tableName: 'slots',
    timestamps: false
});

// 定义Booking模型
const Booking = sequelize.define('Booking', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    slot_id: {
        type: DataTypes.INTEGER,
        allowNull: false
    },
    booking_code: {
        type: DataTypes.STRING(10),
        unique: true,
        allowNull: true
    },
    booker_json: {
        type: DataTypes.TEXT
    },
    created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW
    }
}, {
    tableName: 'bookings',
    timestamps: false
});

// 定义AppConfig模型
const AppConfig = sequelize.define('AppConfig', {
    key: {
        type: DataTypes.STRING(50),
        primaryKey: true
    },
    value: {
        type: DataTypes.STRING(200),
        allowNull: true
    }
}, {
    tableName: 'app_config',
    timestamps: false
});

// 定义Admin-Project关联表
const AdminProjects = sequelize.define('AdminProjects', {
    user_id: {
        type: DataTypes.INTEGER,
        primaryKey: true
    },
    project_id: {
        type: DataTypes.INTEGER,
        primaryKey: true
    }
}, {
    tableName: 'admin_projects',
    timestamps: false
});

// 定义Dispatcher-Group关联表
const DispatcherGroups = sequelize.define('DispatcherGroups', {
    user_id: {
        type: DataTypes.INTEGER,
        primaryKey: true
    },
    group_id: {
        type: DataTypes.INTEGER,
        primaryKey: true
    }
}, {
    tableName: 'dispatcher_groups',
    timestamps: false
});

// 设置关联关系
// Project -> User (dispatchers)
Project.hasMany(User, { foreignKey: 'project_id', as: 'dispatchers' });
User.belongsTo(Project, { foreignKey: 'project_id', as: 'project' });

// Project -> Activity
Project.hasMany(Activity, { foreignKey: 'project_id', as: 'activities', onDelete: 'CASCADE' });
Activity.belongsTo(Project, { foreignKey: 'project_id', as: 'project' });

// Project -> Group
Project.hasMany(Group, { foreignKey: 'project_id', as: 'groups', onDelete: 'CASCADE' });
Group.belongsTo(Project, { foreignKey: 'project_id', as: 'project' });

// Activity -> Slot
Activity.hasMany(Slot, { foreignKey: 'activity_id', as: 'slots', onDelete: 'CASCADE' });
Slot.belongsTo(Activity, { foreignKey: 'activity_id', as: 'activity' });

// Activity -> DispatcherConfig
Activity.hasMany(DispatcherConfig, { foreignKey: 'activity_id', as: 'dispatcher_configs', onDelete: 'CASCADE' });
DispatcherConfig.belongsTo(Activity, { foreignKey: 'activity_id', as: 'activity' });

// Slot -> Booking
Slot.hasMany(Booking, { foreignKey: 'slot_id', as: 'bookings', onDelete: 'CASCADE' });
Booking.belongsTo(Slot, { foreignKey: 'slot_id', as: 'slot' });

// Slot -> User (dispatcher)
Slot.belongsTo(User, { foreignKey: 'dispatcher_id', as: 'dispatcher' });
User.hasMany(Slot, { foreignKey: 'dispatcher_id', as: 'slots' });

// DispatcherConfig -> User
DispatcherConfig.belongsTo(User, { foreignKey: 'dispatcher_id', as: 'dispatcher' });

// 多对多关系: Admin <-> Project
User.belongsToMany(Project, { through: AdminProjects, foreignKey: 'user_id', otherKey: 'project_id', as: 'managed_projects' });
Project.belongsToMany(User, { through: AdminProjects, foreignKey: 'project_id', otherKey: 'user_id', as: 'admins' });

// 多对多关系: User (dispatcher) <-> Group
User.belongsToMany(Group, { through: DispatcherGroups, foreignKey: 'user_id', otherKey: 'group_id', as: 'userGroups' });
Group.belongsToMany(User, { through: DispatcherGroups, foreignKey: 'group_id', otherKey: 'user_id', as: 'dispatchers' });

module.exports = {
    sequelize,
    User,
    Project,
    Group,
    Activity,
    DispatcherConfig,
    Slot,
    Booking,
    AppConfig,
    AdminProjects,
    DispatcherGroups
};
