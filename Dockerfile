FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    wget gnupg git unzip xvfb \
    libgl1 libglx-mesa0 libglu1-mesa libvulkan1 \
    libasound2 libatk-bridge2.0-0 libatk1.0-0 libcups2 libdbus-1-3 \
    libdrm2 libgbm1 libgtk-3-0 libnspr4 libnss3 libx11-xcb1 \
    libxcomposite1 libxdamage1 libxfixes3 libxkbcommon0 libxrandr2 \
    xdg-utils fonts-liberation \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 直接克隆 Python 版求解器
RUN git clone https://github.com/Theyka/Turnstile-Solver.git /app/solver
WORKDIR /app/solver

# 安装 Python 依赖及 patchright 浏览器驱动
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m patchright install chromium

# 回到主目录，安装你的主程序依赖
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir fastapi uvicorn requests

ENV DISPLAY=:99

# 启动：虚拟屏幕 -> 本地 API 服务 -> 你的 FastAPI 主程序
CMD Xvfb :99 -screen 0 1920x1080x24 -ac +extension GLX +render -noreset & \
    export DISPLAY=:99 && \
    cd /app/solver && python api_solver.py --headless false & \
    cd /app && uvicorn main:app --host 0.0.0.0 --port 8000
