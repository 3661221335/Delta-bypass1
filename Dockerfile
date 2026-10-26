FROM python:3.10-slim

# 安装编译 Go 语言的环境和系统依赖
RUN apt-get update && apt-get install -y \
    wget git unzip golang xvfb \
    libgl1 libglx-mesa0 libglu1-mesa libvulkan1 \
    libasound2 libatk-bridge2.0-0 libatk1.0-0 libcups2 libdbus-1-3 \
    libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 libx11-xcb1 \
    libxcomposite1 libxdamage1 libxfixes3 libxkbcommon0 libxrandr2 \
    xdg-utils fonts-liberation \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 下载并编译 Theyka 开源引擎
RUN git clone https://github.com/Theyka/Turnstile-Solver.git /app/solver
WORKDIR /app/solver
RUN go build -o /app/solver_bin main.go

# 回到主目录，安装 Python 依赖
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

ENV DISPLAY=:99

# 启动：拉起虚拟屏幕 -> 启动本地破解引擎(5000端口) -> 启动 B 站主程序(8000端口)
CMD Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset & \
    export DISPLAY=:99 && \
    /app/solver_bin & \
    uvicorn main:app --host 0.0.0.0 --port 8000
