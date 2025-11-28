![Kodawn](https://socialify.git.ci/LYOfficial/Kodawn/image?custom_language=Python&description=1&font=KoHo&forks=1&issues=1&language=1&logo=https%3A%2F%2Foss.1n.hk%2Flyofficial%2Fimages%2Fkodawn.png&name=1&owner=1&pattern=Plus&pulls=1&stargazers=1&theme=Auto)

# KoDawn

> A Self-Service Booking System.
>
> 可待，一款自助放号取号系统。

阁下若对此项目**有所青睐**，还请**移步右上**，点亮那颗**星标**，不胜感谢。

![Python Badge](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white) ![Flask Badge](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white) ![SQLite Badge](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)

**万物有序，可待黎明。**

KoDawn者，可待也，乃集自助放号与取号之能，助君统筹预约事务，无论活动报名、诊室排班，抑或资源分配，皆可井井有条。

## 功能说明



## 使用

`项目管理员`使用教程：

`放号员`使用教程：

`取号员`使用教程：



## 部署

⚠️ **注意事项**
请确保在运行指令前已安装所有依赖 (`pip install -r requirements.txt`)。
如果使用了虚拟环境，请确保先激活虚拟环境。

**1 初始化/创建管理员**

首次部署或需要新增超级管理员时使用。

```bash
flask create-admin
```
作用：按照提示输入用户名和密码，创建一个拥有最高权限的“项目管理员”账号。

**2 启动系统**

```bash
flask run
# 或
python app.py
```

**3 数据库无损升级**

当更新了系统代码（增加了新功能或字段）但不想删除旧数据时使用。

```bash
flask update-db
```
作用：自动检测并添加缺少的数据库表和字段，同时为旧数据补全必要信息（如为旧预约生成取号码），不会丢失现有数据。

**4 查看所有用户**

查看当前系统中所有的管理员和放号员列表。

```bash
flask list-users
```
作用：以表格形式打印出所有用户的 ID、用户名、角色（管理员/放号员）以及所属项目 ID。

**5 修改用户账号/密码**

忘记密码或需要强制修改某人账号时使用。

```bash
flask edit-user
```
作用：交互式指令。先输入要修改的用户 ID（可通过 `list-users` 查看），然后按照提示输入新的用户名或密码。直接按回车键则保持原样不修改。

## 开发

要参与开发和部署这个项目，请先克隆本仓库：

```bash
  git clone https://github.com/LYOfficial/KoDawn.git
```

安装依赖：

```bash
  pip install -r requirements.txt
```

启动开发服务器：

```bash
  flask run
```

## 作者

- [@LYOfficial ](https://github.com/LYOfficial/) 主要开发，项目主管。
