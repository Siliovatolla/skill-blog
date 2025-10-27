# 本地部署 Qwen2.5-Coder-14B 模型完整指南

## 1. 背景与目标

**模型名称：** `itlwas/Qwen2.5-Coder-14B-Instruct-Q4_K_M-GGUF`

### 模型特性：
- 参数量：14B
- 格式：GGUF（4-bit 量化）
- 文件名：`qwen2.5-coder-14b-instruct-q4_k_m.gguf`
- 大小：约 8.99 GB
- 用途：专为代码生成微调，支持 Python/JS/Java/C++ 等

### 笔记本电脑配置：
- CPU：i9-14900HX
- 内存：32GB
- 硬盘：2TB
- 显卡：RTX4060 8G
- 我的 NVIDIA 驱动支持 CUDA 12.5

## 2. 模型下载过程
复制下面链接进行下载
```
https://hf-mirror.com/itlwas/Qwen2.5-Coder-14B-Instruct-Q4_K_M-GGUF
```

如果上面连接打不开就先进去 `https://hf-mirror.com/` 然后搜索下载，找到文件 `qwen2.5-coder-14b-instruct-q4_k_m.gguf`

 下载太慢可以尝试使用其他镜像源或分段下载

## 3. 准备运行环境

下载预编译的 `llama.cpp`（Windows + CUDA 12.4 版本）：
[llama-b6840-bin-win-cuda-12.4-x64.zip](https://github.com/ggerganov/llama.cpp/releases/download/v1.0.0/llama-b6840-bin-win-cuda-12.4-x64.zip)

解压到目录 `C:\llama\` 
在 `C:\llama\` 中创建文件夹`C:\llama\models\qwen2.5-coder-14b-instruct-q4_k_m.gguf` 

## 4. 创建运行脚本

在 `C:\llama\` 目录下创建文件 `run_qwen_coder.bat` ，内容如下：
```
@echo off
cd /d C:\llama
echo 正在启动 Qwen2.5-Coder-14B-Instruct...
echo 请稍候...
.\llama-cli.exe -m .\models\qwen2.5-coder-14b-instruct-q4_k_m.gguf --n-gpu-layers 25 --threads 16 --ctx-size 4096 --temp 0.7 --repeat-penalty 1.1 -n -1
pause
```
## 5. 启动模型
双击 C:\llama\run_qwen_coder.bat
等待模型加载完成
出现提示符 `>` 后，输入代码请求，例如：
```
Write a Python function to reverse a linked list.
```
按回车，模型将生成代码


## 6. 未来升级说明
当 Qwen3-Coder-30B 开源并发布 GGUF 版本后：

下载新模型文件
放入 C:\llama\models\
修改脚本中的 -m 参数指向新文件名
无需重装或重新配置环境，即可直接运行