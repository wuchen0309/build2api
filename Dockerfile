# 使用 slim 版本作为基础（保持不变）
FROM node:18-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量，这是【减肥的关键步骤 1】
# 告诉 Puppeteer 和 Playwright 不要下载它们的浏览器，因为我们要用 Camoufox
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_SKIP_DOWNLOAD=true \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=true \
    NODE_ENV=production

# 1. 安装系统依赖
# 【减肥的关键步骤 2】：添加 --no-install-recommends
# 这可以避免安装几百 MB 的文档、推荐软件包和非必须字体
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    fonts-liberation \
    libasound2 libatk-bridge2.0-0 libatk1.0-0 libc6 libcairo2 libcups2 \
    libdbus-1-3 libexpat1 libfontconfig1 libgbm1 libgcc1 libglib2.0-0 \
    libgtk-3-0 libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 \
    libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 \
    libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 \
    libxtst6 lsb-release wget xdg-utils xvfb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 2. 拷贝 package.json 并安装依赖
COPY package*.json ./

# 【减肥的关键步骤 3】：安装依赖后清理 npm 缓存
# 使用 --omit=dev 确保只安装生产环境依赖
RUN npm install --omit=dev && npm cache clean --force

# 3. 下载 Camoufox (保持原有逻辑，这是必要的体积)
ARG CAMOUFOX_URL
RUN curl -sSL ${CAMOUFOX_URL} -o camoufox-linux.tar.gz && \
    tar -xzf camoufox-linux.tar.gz && \
    rm camoufox-linux.tar.gz && \
    chmod +x /app/camoufox-linux/camoufox

# 4. 拷贝代码
COPY unified-server.js black-browser.js ./

# 5. 权限设置
RUN mkdir -p ./auth && chown -R node:node /app

# 切换用户
USER node

# 暴露端口
EXPOSE 7860 9998

# 环境变量
ENV CAMOUFOX_EXECUTABLE_PATH=/app/camoufox-linux/camoufox

# 启动
CMD ["node", "unified-server.js"]
