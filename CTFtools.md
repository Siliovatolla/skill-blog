# CTF-Tools 项目搭建教程

记录在 Windows 系统上搭建 `ctf-wiki/ctf-tools` 项目的全过程

## 二、正确操作流程

### 1. 打开命令提示符
按下 `Win + R`，输入 `cmd`，回车。

### 2. 创建项目目录
```cmd
D:   #选择自己要安装的盘符
mkdir Projects    #创建Project的文件夹
cd Projects
```
### 3. 克隆项目到本地后进入项目目录

使用 Git 将项目从 GitHub 克隆到本地。

```cmd
git clone https://github.com/ctf-wiki/ctf-tools.git
cd ctf-tools
```
### 4. 创建虚拟环境并激活
在项目根目录下创建一个名为 venv 的虚拟环境。此命令会在当前目录下生成一个名为 venv 的文件夹，其中包含独立的 Python 解释器和包管理环境
```cmd
python -m venv venv
venv\Scripts\activate
```
激活成功后，命令行提示符前会出现 (venv) 标识，表示当前处于虚拟环境中

### 5. 安装项目依赖安装项目依赖
此命令会读取 requirements.txt 文件，并将所有依赖包安装到虚拟环境中，不会影响全局 Python 环境
```
pip install -r requirements.txt
```
### 6. 启动本地服务器并访问
启动 MkDocs 内置的开发服务器
```
mkdocs serve
```
项目启动后，默认监听地址为 http://127.0.0.1:8000，打开游览器访问网址
```
http://localhost:8000
或
http://127.0.0.1:8000
```
### 7. 停止服务器并推出
在cmd中
```
Ctrl + C
然后按Y确认停止服务
deactivate
```
执行后，(venv) 标识会消失，表示已退出虚拟环境，恢复到系统全局环境
