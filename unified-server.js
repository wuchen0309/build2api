const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const express = require("express");
const WebSocket = require("ws");
const http = require("http");
const { EventEmitter } = require("events");
const fs = require("fs");
const path = require("path");
const { firefox } = require("playwright");
const os = require("os");

// ===================================================================================
// AUTH SOURCE MANAGEMENT MODULE
// ===================================================================================

class AuthSource {
  constructor(logger) {
    this.logger = logger;
    this.authMode = "file";
    this.availableIndices = [];
    this.initialIndices = []; 
    this.accountNameMap = new Map();

    if (process.env.AUTH_JSON_1) {
      this.authMode = "env";
      this.logger.info(
        "[Auth] 检测到 AUTH_JSON_1 环境变量，切换到环境变量认证模式。"
      );
    } else {
      this.logger.info(
        '[Auth] 未检测到环境变量认证，将使用 "auth/" 目录下的文件。'
      );
    }

    this._discoverAvailableIndices(); 
    this._preValidateAndFilter(); 

    if (this.availableIndices.length === 0) {
      this.logger.error(
        `[Auth] 致命错误：在 '${this.authMode}' 模式下未找到任何有效的认证源。`
      );
      throw new Error("No valid authentication sources found.");
    }
  }

  _discoverAvailableIndices() {
    let indices = [];
    if (this.authMode === "env") {
      const regex = /^AUTH_JSON_(\d+)$/;
      for (const key in process.env) {
        const match = key.match(regex);
        if (match && match[1]) {
          indices.push(parseInt(match[1], 10));
        }
      }
    } else {
      const authDir = path.join(__dirname, "auth");
      if (!fs.existsSync(authDir)) {
        this.logger.warn('[Auth] "auth/" 目录不存在。');
        this.availableIndices = [];
        return;
      }
      try {
        const files = fs.readdirSync(authDir);
        const authFiles = files.filter((file) => /^auth-\d+\.json$/.test(file));
        indices = authFiles.map((file) =>
          parseInt(file.match(/^auth-(\d+)\.json$/)[1], 10)
        );
      } catch (error) {
        this.logger.error(`[Auth] 扫描 "auth/" 目录失败: ${error.message}`);
        this.availableIndices = [];
        return;
      }
    }

    this.initialIndices = [...new Set(indices)].sort((a, b) => a - b);
    this.availableIndices = [...this.initialIndices]; 

    this.logger.info(
      `[Auth] 在 '${this.authMode}' 模式下，初步发现 ${
        this.initialIndices.length
      } 个认证源: [${this.initialIndices.join(", ")}]`
    );
  }

  _preValidateAndFilter() {
    if (this.availableIndices.length === 0) return;

    this.logger.info("[Auth] 开始预检验所有认证源的JSON格式...");
    const validIndices = [];
    const invalidSourceDescriptions = [];

    for (const index of this.availableIndices) {
      const authContent = this._getAuthContent(index);
      if (authContent) {
        try {
          const authData = JSON.parse(authContent);
          validIndices.push(index);
          this.accountNameMap.set(
            index,
            authData.accountName || "N/A (未命名)"
          );
        } catch (e) {
          invalidSourceDescriptions.push(`auth-${index}`);
        }
      } else {
        invalidSourceDescriptions.push(`auth-${index} (无法读取)`);
      }
    }

    if (invalidSourceDescriptions.length > 0) {
      this.logger.warn(
        `⚠️ [Auth] 预检验发现 ${
          invalidSourceDescriptions.length
        } 个格式错误或无法读取的认证源: [${invalidSourceDescriptions.join(
          ", "
        )}]，将从可用列表中移除。`
      );
    }

    this.availableIndices = validIndices;
  }

  _getAuthContent(index) {
    if (this.authMode === "env") {
      return process.env[`AUTH_JSON_${index}`];
    } else {
      const authFilePath = path.join(__dirname, "auth", `auth-${index}.json`);
      if (!fs.existsSync(authFilePath)) return null;
      try {
        return fs.readFileSync(authFilePath, "utf-8");
      } catch (e) {
        return null;
      }
    }
  }

  getAuth(index) {
    if (!this.availableIndices.includes(index)) {
      this.logger.error(`[Auth] 请求了无效或不存在的认证索引: ${index}`);
      return null;
    }

    let jsonString = this._getAuthContent(index);
    if (!jsonString) {
      this.logger.error(`[Auth] 在读取时无法获取认证源 #${index} 的内容。`);
      return null;
    }

    try {
      return JSON.parse(jsonString);
    } catch (e) {
      this.logger.error(
        `[Auth] 解析来自认证源 #${index} 的JSON内容失败: ${e.message}`
      );
      return null;
    }
  }
  
  getMaxIndex() {
    return Math.max(...this.availableIndices, 0);
  }
}

// ===================================================================================
// BROWSER MANAGEMENT MODULE
// ===================================================================================

class BrowserManager {
  constructor(logger, config, authSource) {
    this.logger = logger;
    this.config = config;
    this.authSource = authSource;
    this.browser = null;
    this.context = null;
    this.page = null;
    this.currentAuthIndex = 0;
    this.scriptFileName = "black-browser.js";
    this.launchArgs = [
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-infobars",
      "--disable-background-networking",
      "--disable-default-apps",
      "--disable-extensions",
      "--disable-sync",
      "--disable-translate",
      "--metrics-recording-only",
      "--mute-audio",
      "--safebrowsing-disable-auto-update",
    ];

    if (this.config.browserExecutablePath) {
      this.browserExecutablePath = this.config.browserExecutablePath;
    } else {
      const platform = os.platform();
      if (platform === "linux") {
        this.browserExecutablePath = path.join(
          __dirname,
          "camoufox-linux",
          "camoufox"
        );
      } else {
        throw new Error(`Unsupported operating system: ${platform}`);
      }
    }
  }

  async launchOrSwitchContext(authIndex) {
    if (!this.browser) {
      this.logger.info("🚀 [Browser] 浏览器实例未运行，正在进行首次启动...");
      if (!fs.existsSync(this.browserExecutablePath)) {
        throw new Error(
          `Browser executable not found at path: ${this.browserExecutablePath}`
        );
      }
      this.browser = await firefox.launch({
        headless: true,
        executablePath: this.browserExecutablePath,
        args: this.launchArgs,
      });
      this.browser.on("disconnected", () => {
        this.logger.error("❌ [Browser] 浏览器意外断开连接！(可能是资源不足)");
        this.browser = null;
        this.context = null;
        this.page = null;
      });
      this.logger.info("✅ [Browser] 浏览器实例已成功启动。");
    }
    if (this.context) {
      this.logger.info("[Browser] 正在关闭旧的浏览器上下文...");
      await this.context.close();
      this.context = null;
      this.page = null;
      this.logger.info("[Browser] 旧上下文已关闭。");
    }

    const sourceDescription =
      this.authSource.authMode === "env"
        ? `环境变量 AUTH_JSON_${authIndex}`
        : `文件 auth-${authIndex}.json`;
    this.logger.info("==================================================");
    this.logger.info(
      `🔄 [Browser] 正在为账号 #${authIndex} 创建新的浏览器上下文`
    );
    this.logger.info(`   • 认证源: ${sourceDescription}`);
    this.logger.info("==================================================");

    const storageStateObject = this.authSource.getAuth(authIndex);
    if (!storageStateObject) {
      throw new Error(
        `Failed to get or parse auth source for index ${authIndex}.`
      );
    }
    const buildScriptContent = fs.readFileSync(
      path.join(__dirname, this.scriptFileName),
      "utf-8"
    );

    try {
      this.context = await this.browser.newContext({
        storageState: storageStateObject,
        viewport: { width: 1920, height: 1080 },
      });
      this.page = await this.context.newPage();
      this.page.on("console", (msg) => {
        const msgText = msg.text();
        if (msgText.includes("[ProxyClient]")) {
          this.logger.info(
            `[Browser] ${msgText.replace("[ProxyClient] ", "")}`
          );
        } else if (msg.type() === "error") {
          this.logger.error(`[Browser Page Error] ${msgText}`);
        }
      });

      this.logger.info(`[Browser] 正在导航至目标网页...`);
      const targetUrl =
        "https://aistudio.google.com/u/0/apps/bundled/blank?showPreview=true&showCode=true&showAssistant=true";
      await this.page.goto(targetUrl, {
        timeout: 180000,
        waitUntil: "domcontentloaded",
      });
      this.logger.info("[Browser] 页面加载完成。");

      await this.page.waitForTimeout(3000);

      this.logger.info(`[Browser] 正在检查 Cookie 同意横幅...`);
      try {
        const agreeButton = this.page.locator('button:text("Agree")');
        await agreeButton.waitFor({ state: "visible", timeout: 10000 });
        this.logger.info(
          `[Browser] ✅ 发现 Cookie 同意横幅，正在点击 "Agree"...`
        );
        await agreeButton.click({ force: true });
        await this.page.waitForTimeout(1000);
      } catch (error) {
        this.logger.info(`[Browser] 未发现 Cookie 同意横幅，跳过。`);
      }

      this.logger.info(`[Browser] 正在检查 "Got it" 弹窗...`);
      try {
        const gotItButton = this.page.locator(
          'div.dialog button:text("Got it")'
        );
        await gotItButton.waitFor({ state: "visible", timeout: 15000 });
        this.logger.info(`[Browser] ✅ 发现 "Got it" 弹窗，正在点击...`);
        await gotItButton.click({ force: true });
        await this.page.waitForTimeout(1000);
      } catch (error) {
        this.logger.info(`[Browser] 未发现 "Got it" 弹窗，跳过。`);
      }

      this.logger.info(`[Browser] 正在检查新手引导...`);
      try {
        const closeButton = this.page.locator('button[aria-label="Close"]');
        await closeButton.waitFor({ state: "visible", timeout: 15000 });
        this.logger.info(`[Browser] ✅ 发现新手引导弹窗，正在点击关闭按钮...`);
        await closeButton.click({ force: true });
        await this.page.waitForTimeout(1000);
      } catch (error) {
        this.logger.info(
          `[Browser] 未发现 "It's time to build" 新手引导，跳过。`
        );
      }

      this.logger.info("[Browser] 准备UI交互，强行移除所有可能的遮罩层...");
      await this.page.evaluate(() => {
        const overlays = document.querySelectorAll("div.cdk-overlay-backdrop");
        if (overlays.length > 0) {
          console.log(
            `[ProxyClient] (内部JS) 发现并移除了 ${overlays.length} 个遮罩层。`
          );
          overlays.forEach((el) => el.remove());
        }
      });

      this.logger.info('[Browser] (步骤1/5) 准备点击 "Code" 按钮...');

      // 等待按钮出现（但不死等它可点击，只等它存在于DOM中）
      try {
        await this.page.waitForSelector('button:has-text("Code")', { state: 'attached', timeout: 15000 });
      } catch (e) {
        this.logger.warn("等待 Code 按钮 DOM 出现超时，尝试直接盲点...");
      }

      for (let i = 1; i <= 5; i++) {
        try {
          this.logger.info(`  [尝试 ${i}/5] 执行多策略点击...`);

          // --- 策略 A: Playwright 暴力点击 (force: true 无视遮罩) ---
          let clicked = false;
          try {
            const codeBtn = this.page.locator('button:text("Code")').first();
            if (await codeBtn.count() > 0) {
              // force: true 是关键，它会跳过 Playwright 的 "可见性" 和 "遮挡" 检查
              await codeBtn.click({ force: true, timeout: 3000 });
              this.logger.info("  ✅ (策略A) Playwright 强制点击成功！");
              clicked = true;
            }
          } catch (e) { /* 忽略 A 失败 */ }

          if (clicked) break;

          // --- 策略 B: 原生 JS 注入点击 (穿透力最强) ---
          const jsResult = await this.page.evaluate(() => {
            const buttons = Array.from(document.querySelectorAll('button'));
            const target = buttons.find(b => b.innerText && b.innerText.trim() === 'Code');
            if (target) {
              // HTMLElement.click() 是浏览器原生行为，完全无视界面遮罩
              target.click();
              return true;
            }
            return false;
          });

          if (jsResult) {
            this.logger.info("  ✅ (策略B) 原生 JS 点击触发成功！");
            break;
          }

          // --- 策略 C: 模拟鼠标事件 (兜底方案) ---
          const dispatchResult = await this.page.evaluate(() => {
            const buttons = Array.from(document.querySelectorAll('button'));
            const target = buttons.find(b => b.innerText && b.innerText.trim() === 'Code');
            if (target) {
              const evt = new MouseEvent('click', { bubbles: true, cancelable: true, view: window });
              target.dispatchEvent(evt);
              return true;
            }
            return false;
          });

          if (dispatchResult) {
            this.logger.info("  ✅ (策略C) 鼠标事件派发成功！");
            break;
          }

          this.logger.warn(`  [尝试 ${i}/5] 本轮点击未生效，清理环境后重试...`);

          // 只有在点击失败后，才尝试清理遮罩，防止误删正常元素
          await this.page.evaluate(() => {
            document.querySelectorAll('.cdk-overlay-backdrop, .cdk-overlay-container').forEach(e => e.remove());
          });

          await this.page.waitForTimeout(1000);

          if (i === 5) {
            // 保存截图以便调试
            const screenshotPath = path.join(__dirname, "debug_failure_click.png");
            await this.page.screenshot({ path: screenshotPath, fullPage: true }).catch(() => {});
            throw new Error("所有点击策略耗尽，无法打开代码编辑器。");
          }
        } catch (error) {
          this.logger.warn(`  [尝试 ${i}/5] 异常: ${error.message}`);
          if (i === 5) throw error;
        }
      }

      this.logger.info(
        '[Browser] (步骤2/5) "Code" 按钮点击成功，等待编辑器变为可见...'
      );
      const editorContainerLocator = this.page
        .locator("div.monaco-editor")
        .first();
      await editorContainerLocator.waitFor({
        state: "visible",
        timeout: 60000,
      });

      this.logger.info(
        "[Browser] (清场 #2) 准备点击编辑器，再次强行移除所有可能的遮罩层..."
      );
      await this.page.evaluate(() => {
        const overlays = document.querySelectorAll("div.cdk-overlay-backdrop");
        if (overlays.length > 0) {
          console.log(
            `[ProxyClient] (内部JS) 发现并移除了 ${overlays.length} 个新出现的遮罩层。`
          );
          overlays.forEach((el) => el.remove());
        }
      });
      await this.page.waitForTimeout(250);

      this.logger.info("[Browser] (步骤3/5) 编辑器已显示，聚焦并粘贴脚本...");
      await editorContainerLocator.click({ timeout: 30000 });

      await this.page.evaluate(
        (text) => navigator.clipboard.writeText(text),
        buildScriptContent
      );
      const isMac = os.platform() === "darwin";
      const pasteKey = isMac ? "Meta+V" : "Control+V";
      await this.page.keyboard.press(pasteKey);
      this.logger.info("[Browser] (步骤4/5) 脚本已粘贴。");
      this.logger.info(
        '[Browser] (步骤5/5) 正在点击 "Preview" 按钮以使脚本生效...'
      );
      await this.page.locator('button:text("Preview")').click();
      this.logger.info("[Browser] ✅ UI交互完成，脚本已开始运行。");
      this.currentAuthIndex = authIndex;
      this.logger.info("==================================================");
      this.logger.info(`✅ [Browser] 账号 ${authIndex} 的上下文初始化成功！`);
      this.logger.info("✅ [Browser] 浏览器客户端已准备就绪。");
      this.logger.info("==================================================");
    } catch (error) {
      this.logger.error(
        `❌ [Browser] 账户 ${authIndex} 的上下文初始化失败: ${error.message}`
      );
      if (this.browser) {
        await this.browser.close();
        this.browser = null;
      }
      throw error;
    }
  }

  async closeBrowser() {
    if (this.browser) {
      this.logger.info("[Browser] 正在关闭整个浏览器实例...");
      await this.browser.close();
      this.browser = null;
      this.context = null;
      this.page = null;
      this.logger.info("[Browser] 浏览器实例已关闭。");
    }
  }

  async switchAccount(newAuthIndex) {
    this.logger.info(
      `🔄 [Browser] 开始账号切换: 从 ${this.currentAuthIndex} 到 ${newAuthIndex}`
    );
    await this.launchOrSwitchContext(newAuthIndex);
    this.logger.info(
      `✅ [Browser] 账号切换完成，当前账号: ${this.currentAuthIndex}`
    );
  }
}

// ===================================================================================
// PROXY SERVER MODULE
// ===================================================================================

class LoggingService {
  constructor(serviceName = "ProxyServer") {
    this.serviceName = serviceName;
    this.logBuffer = []; 
    this.maxBufferSize = 100; 
  }

  _formatMessage(level, message) {
    const timestamp = new Date().toISOString();
    const formatted = `[${level}] ${timestamp} [${this.serviceName}] - ${message}`;

    this.logBuffer.push(formatted);
    if (this.logBuffer.length > this.maxBufferSize) {
      this.logBuffer.shift();
    }

    return formatted;
  }

  info(message) {
    console.log(this._formatMessage("INFO", message));
  }
  error(message) {
    console.error(this._formatMessage("ERROR", message));
  }
  warn(message) {
    console.warn(this._formatMessage("WARN", message));
  }
  debug(message) {
    console.debug(this._formatMessage("DEBUG", message));
  }
}

class MessageQueue extends EventEmitter {
  constructor(timeoutMs = 600000) {
    super();
    this.messages = [];
    this.waitingResolvers = [];
    this.defaultTimeout = timeoutMs;
    this.closed = false;
  }
  enqueue(message) {
    if (this.closed) return;
    if (this.waitingResolvers.length > 0) {
      const resolver = this.waitingResolvers.shift();
      resolver.resolve(message);
    } else {
      this.messages.push(message);
    }
  }
  async dequeue(timeoutMs = this.defaultTimeout) {
    if (this.closed) {
      throw new Error("Queue is closed");
    }
    return new Promise((resolve, reject) => {
      if (this.messages.length > 0) {
        resolve(this.messages.shift());
        return;
      }
      const resolver = { resolve, reject };
      this.waitingResolvers.push(resolver);
      const timeoutId = setTimeout(() => {
        const index = this.waitingResolvers.indexOf(resolver);
        if (index !== -1) {
          this.waitingResolvers.splice(index, 1);
          reject(new Error("Queue timeout"));
        }
      }, timeoutMs);
      resolver.timeoutId = timeoutId;
    });
  }
  close() {
    this.closed = true;
    this.waitingResolvers.forEach((resolver) => {
      clearTimeout(resolver.timeoutId);
      resolver.reject(new Error("Queue closed"));
    });
    this.waitingResolvers = [];
    this.messages = [];
  }
}

class ConnectionRegistry extends EventEmitter {
  constructor(logger) {
    super();
    this.logger = logger;
    this.connections = new Set();
    this.messageQueues = new Map();
    this.reconnectGraceTimer = null; 
  }
  addConnection(websocket, clientInfo) {
    if (this.reconnectGraceTimer) {
      clearTimeout(this.reconnectGraceTimer);
      this.reconnectGraceTimer = null;
      this.logger.info("[Server] 在缓冲期内检测到新连接，已取消断开处理。");
    }

    this.connections.add(websocket);
    this.logger.info(
      `[Server] 内部WebSocket客户端已连接 (来自: ${clientInfo.address})`
    );
    websocket.on("message", (data) =>
      this._handleIncomingMessage(data.toString())
    );
    websocket.on("close", () => this._removeConnection(websocket));
    websocket.on("error", (error) =>
      this.logger.error(`[Server] 内部WebSocket连接错误: ${error.message}`)
    );
    this.emit("connectionAdded", websocket);
  }

  _removeConnection(websocket) {
    this.connections.delete(websocket);
    this.logger.warn("[Server] 内部WebSocket客户端连接断开。");

    this.logger.info("[Server] 启动5秒重连缓冲期...");
    this.reconnectGraceTimer = setTimeout(() => {
      this.logger.error(
        "[Server] 缓冲期结束，未检测到重连。确认连接丢失，正在清理所有待处理请求..."
      );
      this.messageQueues.forEach((queue) => queue.close());
      this.messageQueues.clear();
      this.emit("connectionLost"); 
    }, 5000); 

    this.emit("connectionRemoved", websocket);
  }

  _handleIncomingMessage(messageData) {
    try {
      const parsedMessage = JSON.parse(messageData);
      const requestId = parsedMessage.request_id;
      if (!requestId) {
        this.logger.warn("[Server] 收到无效消息：缺少request_id");
        return;
      }
      const queue = this.messageQueues.get(requestId);
      if (queue) {
        this._routeMessage(parsedMessage, queue);
      } else {
        this.logger.warn(`[Server] 收到未知或已过时请求ID的消息: ${requestId}`);
      }
    } catch (error) {
      this.logger.error("[Server] 解析内部WebSocket消息失败");
    }
  }

  _routeMessage(message, queue) {
    const { event_type } = message;
    switch (event_type) {
      case "response_headers":
      case "chunk":
      case "error":
        queue.enqueue(message);
        break;
      case "stream_close":
        queue.enqueue({ type: "STREAM_END" });
        break;
      default:
        this.logger.warn(`[Server] 未知的内部事件类型: ${event_type}`);
    }
  }
  hasActiveConnections() {
    return this.connections.size > 0;
  }
  getFirstConnection() {
    return this.connections.values().next().value;
  }
  createMessageQueue(requestId) {
    const queue = new MessageQueue();
    this.messageQueues.set(requestId, queue);
    return queue;
  }
  removeMessageQueue(requestId) {
    const queue = this.messageQueues.get(requestId);
    if (queue) {
      queue.close();
      this.messageQueues.delete(requestId);
    }
  }
}

class RequestHandler {
  constructor(
    serverSystem,
    connectionRegistry,
    logger,
    browserManager,
    config,
    authSource
  ) {
    this.serverSystem = serverSystem;
    this.connectionRegistry = connectionRegistry;
    this.logger = logger;
    this.browserManager = browserManager;
    this.config = config;
    this.authSource = authSource;
    this.maxRetries = this.config.maxRetries;
    this.retryDelay = this.config.retryDelay;
    this.failureCount = 0;
    this.usageCount = 0;
    
    // [修改] 新增并发控制状态
    this.activeRequestCount = 0; 
    this.pendingSwitch = false;  
    this.isAuthSwitching = false;
    this.isSystemBusy = false;
  }

  get currentAuthIndex() {
    return this.browserManager.currentAuthIndex;
  }

  _getMaxAuthIndex() {
    return this.authSource.getMaxIndex();
  }

  _getNextAuthIndex() {
    const available = this.authSource.availableIndices; 
    if (available.length === 0) return null;

    const currentIndexInArray = available.indexOf(this.currentAuthIndex);
    // 如果当前账号不在可用列表中，或者找不到，从第一个开始
    if (currentIndexInArray === -1) {
      return available[0];
    }
    const nextIndexInArray = (currentIndexInArray + 1) % available.length;
    return available[nextIndexInArray];
  }

  // [新增] 尝试执行挂起的切换任务
  async _tryExecutePendingSwitch() {
    if (this.pendingSwitch && this.activeRequestCount === 0 && !this.isAuthSwitching) {
        this.logger.info(`[Auth] ⚡ 所有活跃请求已结束，开始执行挂起的账号切换...`);
        try {
            await this._switchToNextAuth();
        } catch (err) {
            this.logger.error(`[Auth] 挂起的账号切换任务失败: ${err.message}`);
        } finally {
            this.pendingSwitch = false; 
        }
    }
  }

  async _switchToNextAuth() {
    if (this.isAuthSwitching) {
      this.logger.info("🔄 [Auth] 正在切换账号，跳过重复操作");
      return { success: false, reason: "Switch already in progress." };
    }

    this.isSystemBusy = true;
    this.isAuthSwitching = true;

    try {
      const previousAuthIndex = this.currentAuthIndex;
      const nextAuthIndex = this._getNextAuthIndex();

      this.logger.info("==================================================");
      this.logger.info(`🔄 [Auth] 开始账号切换流程`);
      this.logger.info(`   • 当前账号: #${previousAuthIndex}`);
      this.logger.info(`   • 目标账号: #${nextAuthIndex}`);
      this.logger.info("==================================================");

      try {
        await this.browserManager.switchAccount(nextAuthIndex);
        this.failureCount = 0;
        this.usageCount = 0;
        this.logger.info(
          `✅ [Auth] 成功切换到账号 #${this.currentAuthIndex}，计数已重置。`
        );
        return { success: true, newIndex: this.currentAuthIndex };
      } catch (error) {
        this.logger.error(
          `❌ [Auth] 切换到账号 #${nextAuthIndex} 失败: ${error.message}`
        );
        this.logger.warn(
          `🚨 [Auth] 切换失败，正在尝试回退到上一个可用账号 #${previousAuthIndex}...`
        );
        try {
          await this.browserManager.launchOrSwitchContext(previousAuthIndex);
          this.logger.info(`✅ [Auth] 成功回退到账号 #${previousAuthIndex}！`);
          this.failureCount = 0;
          this.usageCount = 0;
          this.logger.info("[Auth] 失败和使用计数已在回退成功后重置为0。");
          return {
            success: false,
            fallback: true,
            newIndex: this.currentAuthIndex,
          };
        } catch (fallbackError) {
          this.logger.error(
            `FATAL: ❌❌❌ [Auth] 紧急回退到账号 #${previousAuthIndex} 也失败了！服务可能中断。`
          );
          throw fallbackError;
        }
      }
    } finally {
      this.isAuthSwitching = false;
      this.isSystemBusy = false;
    }
  }

  async _switchToSpecificAuth(targetIndex) {
    if (this.isAuthSwitching) {
      this.logger.info("🔄 [Auth] 正在切换账号，跳过重复操作");
      return { success: false, reason: "Switch already in progress." };
    }
    
    // 如果是手动强切，虽然不强制等待 activeRequestCount 为 0，但给个警告
    if (this.activeRequestCount > 0) {
       this.logger.warn(`⚠️ [Auth] 正在强制切换账号，但当前仍有 ${this.activeRequestCount} 个请求正在处理中，可能会被中断。`);
    }

    if (!this.authSource.availableIndices.includes(targetIndex)) {
      return {
        success: false,
        reason: `切换失败：账号 #${targetIndex} 无效或不存在。`,
      };
    }

    this.isSystemBusy = true;
    this.isAuthSwitching = true;
    try {
      this.logger.info(`🔄 [Auth] 开始切换到指定账号 #${targetIndex}...`);
      await this.browserManager.switchAccount(targetIndex);
      this.failureCount = 0;
      this.usageCount = 0;
      this.pendingSwitch = false; // 手动切换成功后，清除可能存在的自动切换标记
      this.logger.info(
        `✅ [Auth] 成功切换到账号 #${this.currentAuthIndex}，计数已重置。`
      );
      return { success: true, newIndex: this.currentAuthIndex };
    } catch (error) {
      this.logger.error(
        `❌ [Auth] 切换到指定账号 #${targetIndex} 失败: ${error.message}`
      );
      throw error;
    } finally {
      this.isAuthSwitching = false;
      this.isSystemBusy = false;
    }
  }

  async _handleRequestFailureAndSwitch(errorDetails, res) {
    if (this.config.failureThreshold > 0) {
      this.failureCount++;
      this.logger.warn(
        `⚠️ [Auth] 请求失败 - 失败计数: ${this.failureCount}/${this.config.failureThreshold} (当前账号索引: ${this.currentAuthIndex})`
      );
    }

    const isImmediateSwitch = this.config.immediateSwitchStatusCodes.includes(
      errorDetails.status
    );
    const isThresholdReached =
      this.config.failureThreshold > 0 &&
      this.failureCount >= this.config.failureThreshold;

    if (isImmediateSwitch || isThresholdReached) {
      if (isImmediateSwitch) {
        this.logger.warn(
          `🔴 [Auth] 收到状态码 ${errorDetails.status}，触发立即切换账号...`
        );
      } else {
        this.logger.warn(
          `🔴 [Auth] 达到失败阈值 (${this.failureCount}/${this.config.failureThreshold})！准备切换账号...`
        );
      }

      try {
        const result = await this._switchToNextAuth();
        
        // [修改] 根据切换结果决定返回给客户端的信息
        if (result.success) {
             const msg = `✅ 检测到请求异常，已自动切换到新账号 #${result.newIndex}。请重试请求。`;
             this.logger.info(`[Auth] ${msg}`);
             // 切换成功通常不需要发 error chunk，除非是在流中间断开，这里选择记录日志
        } else if (result.fallback) {
             const successMessage = `🔄 目标账户无效，已自动回退至账号 #${this.currentAuthIndex}。`;
             this.logger.info(`[Auth] ${successMessage}`);
             if (res) this._sendErrorChunkToClient(res, successMessage);
        }

      } catch (error) {
        let userMessage = `❌ 致命错误：发生未知切换错误: ${error.message}`;

        if (error.message.includes("Only one account is available")) {
          userMessage = "❌ 切换失败：只有一个可用账号。";
          this.logger.info("[Auth] 只有一个可用账号，失败计数已重置。");
          this.failureCount = 0;
        } else if (error.message.includes("回退失败原因")) {
          userMessage = `❌ 致命错误：自动切换和紧急回退均失败，服务可能已中断，请检查日志！`;
        } else if (error.message.includes("切换到账号")) {
          userMessage = `⚠️ 自动切换失败：已自动回退到账号 #${this.currentAuthIndex}，请检查目标账号是否存在问题。`;
        }

        this.logger.error(`[Auth] 后台账号切换任务最终失败: ${error.message}`);
        if (res) this._sendErrorChunkToClient(res, userMessage);
      }
      return;
    }
  }

  // [修改] Google 原生请求处理 (支持 graceful switch)
  async processRequest(req, res) {
    // 1. 检查是否正在等待切换，如果是，拒绝新请求以排空队列
    if (this.pendingSwitch || this.isAuthSwitching) {
         this.logger.warn("[System] 系统正在等待/进行账号切换，拒绝新请求以排空队列。");
         return this._sendErrorResponse(res, 503, "Server is rotating accounts, please retry shortly.");
    }
    
    // 2. 增加活跃计数
    this.activeRequestCount++;

    const requestId = this._generateRequestId();
    res.on("close", () => {
      if (!res.writableEnded) {
        this.logger.warn(
          `[Request] 客户端已提前关闭请求 #${requestId} 的连接。`
        );
        this._cancelBrowserRequest(requestId);
      }
    });

    // 崩溃恢复逻辑
    if (!this.connectionRegistry.hasActiveConnections()) {
      if (this.isSystemBusy) {
        this.activeRequestCount--; // 退出前减少计数
        this.logger.warn("[System] 检测到连接断开，但系统正在进行切换/恢复，拒绝新请求。");
        return this._sendErrorResponse(res, 503, "服务器正在进行内部维护（账号切换/恢复），请稍后重试。");
      }

      this.logger.error("❌ [System] 检测到浏览器WebSocket连接已断开！可能是进程崩溃。正在尝试恢复...");
      this.isSystemBusy = true;
      try {
        await this.browserManager.launchOrSwitchContext(this.currentAuthIndex);
        this.logger.info(`✅ [System] 浏览器已成功恢复！`);
      } catch (error) {
        this.activeRequestCount--; // 退出前减少计数
        this.isSystemBusy = false; // 恢复失败也要解除 busy
        this.logger.error(`❌ [System] 浏览器自动恢复失败: ${error.message}`);
        return this._sendErrorResponse(res, 503, "服务暂时不可用：后端浏览器实例崩溃且无法自动恢复，请联系管理员。");
      } finally {
        this.isSystemBusy = false;
      }
    }

    if (this.isSystemBusy) {
      this.activeRequestCount--;
      this.logger.warn("[System] 收到新请求，但系统正在进行切换/恢复，拒绝新请求。");
      return this._sendErrorResponse(res, 503, "服务器正在进行内部维护（账号切换/恢复），请稍后重试。");
    }

    const isGenerativeRequest =
      req.method === "POST" &&
      (req.path.includes("generateContent") ||
        req.path.includes("streamGenerateContent"));
        
    // [修改] 计数逻辑：只有在没挂起切换时才增加使用计数
    if (this.config.switchOnUses > 0 && isGenerativeRequest && !this.pendingSwitch) {
      this.usageCount++;
      this.logger.info(
        `[Request] 生成请求 - 账号轮换计数: ${this.usageCount}/${this.config.switchOnUses} (当前账号: ${this.currentAuthIndex})`
      );
      if (this.usageCount >= this.config.switchOnUses) {
        this.pendingSwitch = true; // 标记需要切换
        this.logger.info(`[Auth] ⚠️ 达到轮换阈值，将在当前所有请求结束后自动切换账号。`);
      }
    }

    const proxyRequest = this._buildProxyRequest(req, requestId);
    proxyRequest.is_generative = isGenerativeRequest;
    const messageQueue = this.connectionRegistry.createMessageQueue(requestId);
    const wantsStreamByHeader = req.headers.accept && req.headers.accept.includes("text/event-stream");
    const wantsStreamByPath = req.path.includes(":streamGenerateContent");
    const wantsStream = wantsStreamByHeader || wantsStreamByPath;

    try {
      if (wantsStream) {
        this.logger.info(
          `[Request] 客户端启用流式传输 (${this.serverSystem.streamingMode})，进入流式处理模式...`
        );
        if (this.serverSystem.streamingMode === "fake") {
          await this._handlePseudoStreamResponse(proxyRequest, messageQueue, req, res);
        } else {
          await this._handleRealStreamResponse(proxyRequest, messageQueue, res);
        }
      } else {
        proxyRequest.streaming_mode = "fake";
        await this._handleNonStreamResponse(proxyRequest, messageQueue, res);
      }
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      this.connectionRegistry.removeMessageQueue(requestId);
      
      // [核心] 请求结束，减少活跃计数，并检查是否可以执行切换
      this.activeRequestCount--;
      if (this.activeRequestCount < 0) this.activeRequestCount = 0;
      this._tryExecutePendingSwitch();
    }
  }

  // [修改] OpenAI 请求处理 (支持 graceful switch)
  async processOpenAIRequest(req, res) {
    // 1. 检查挂起状态
    if (this.pendingSwitch || this.isAuthSwitching) {
         return this._sendErrorResponse(res, 503, "Server is rotating accounts, please retry shortly.");
    }
    
    // 2. 增加活跃计数
    this.activeRequestCount++;
    
    // 计数逻辑 (OpenAI 也要算)
    if (this.config.switchOnUses > 0 && !this.pendingSwitch) {
         this.usageCount++;
         this.logger.info(`[Request] OpenAI请求 - 账号轮换计数: ${this.usageCount}/${this.config.switchOnUses}`);
         if (this.usageCount >= this.config.switchOnUses) {
             this.pendingSwitch = true;
             this.logger.info(`[Auth] ⚠️ 达到轮换阈值 (OpenAI)，将在请求结束后切换。`);
         }
    }

    const requestId = this._generateRequestId();
    const isOpenAIStream = req.body.stream === true;
    const model = req.body.model || "gemini-1.5-pro-latest";

    let googleBody;
    try {
      googleBody = this._translateOpenAIToGoogle(req.body, model);
    } catch (error) {
      this.activeRequestCount--; // 错误返回前减少计数
      this.logger.error(`[Adapter] OpenAI请求翻译失败: ${error.message}`);
      return this._sendErrorResponse(res, 400, "Invalid OpenAI request format.");
    }

    const googleEndpoint = isOpenAIStream
      ? "streamGenerateContent"
      : "generateContent";
    const proxyRequest = {
      path: `/v1beta/models/${model}:${googleEndpoint}`,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      query_params: isOpenAIStream ? { alt: "sse" } : {},
      body: JSON.stringify(googleBody),
      request_id: requestId,
      is_generative: true,
      streaming_mode: "real",
      client_wants_stream: true,
      resume_on_prohibit: this.serverSystem.enableResume,
      resume_limit: this.serverSystem.resumeLimit 
    };

    const messageQueue = this.connectionRegistry.createMessageQueue(requestId);

    try {
      this._forwardRequest(proxyRequest);
      const initialMessage = await messageQueue.dequeue(); 

      if (initialMessage.event_type === "error") {
        this.logger.error(
          `[Adapter] 收到来自浏览器的错误，将触发切换逻辑。状态码: ${initialMessage.status}, 消息: ${initialMessage.message}`
        );

        await this._handleRequestFailureAndSwitch(initialMessage, res);

        if (isOpenAIStream) {
          if (!res.writableEnded) {
            res.write("data: [DONE]\n\n");
            res.end();
          }
        } else {
          this._sendErrorResponse(
            res,
            initialMessage.status || 500,
            initialMessage.message
          );
        }
        return; 
      }

      if (this.failureCount > 0) {
        this.logger.info(
          `✅ [Auth] OpenAI接口请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
        );
        this.failureCount = 0;
      }
      
      let capturedFinishReason = "UNKNOWN";

      if (isOpenAIStream) {
        res.status(200).set({
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });

        let lastGoogleChunk = "";
        while (true) {
          const message = await messageQueue.dequeue(300000); 
          if (message.type === "STREAM_END") {
            res.write("data: [DONE]\n\n");
            break;
          }
          if (message.data) {
            const match = message.data.match(/"finishReason"\s*:\s*"([^"]+)"/);
            if (match && match[1]) {
                capturedFinishReason = match[1];
            }

            const translatedChunk = this._translateGoogleToOpenAIStream(
              message.data,
              model
            );
            if (translatedChunk) {
              res.write(translatedChunk);
            }
            lastGoogleChunk = message.data; 
          }
        }

        try {
          if (capturedFinishReason === "UNKNOWN" && lastGoogleChunk.startsWith("data: ")) {
            const jsonString = lastGoogleChunk.substring(6).trim();
            if (jsonString) {
              const lastResponse = JSON.parse(jsonString);
              capturedFinishReason = lastResponse.candidates?.[0]?.finishReason || "UNKNOWN";
            }
          }
        } catch (e) {
        }
        
        this.logger.info(
            `✅ [Request] OpenAI流式响应结束，原因: ${capturedFinishReason}，请求ID: ${requestId}`
        );
        
      } else {
        let fullBody = "";
        while (true) {
          const message = await messageQueue.dequeue(300000);
          if (message.type === "STREAM_END") {
            break;
          }
          if (message.event_type === "chunk" && message.data) {
            fullBody += message.data;
          }
        }

        const googleResponse = JSON.parse(fullBody);
        const candidate = googleResponse.candidates?.[0];

        let responseContent = "";
        let responseReasoning = ""; 

        if (
          candidate &&
          candidate.content &&
          Array.isArray(candidate.content.parts)
        ) {
          candidate.content.parts.forEach(p => {
            if (p.inlineData) {
                const image = p.inlineData;
                responseContent += `![Generated Image](data:${image.mimeType};base64,${image.data})\n`;
                this.logger.info("[Adapter] 从 parts.inlineData 中成功解析到图片。");
            } else if (p.thought) {
                responseReasoning += (p.text || "");
            } else {
                responseContent += (p.text || ""); 
            }
          });
        }

        const openaiResponse = {
          id: `chatcmpl-${requestId}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: model,
          choices: [
            {
              index: 0,
              message: { 
                  role: "assistant", 
                  content: responseContent,
                  reasoning_content: responseReasoning || null 
              },
              finish_reason: candidate?.finishReason || "UNKNOWN",
            },
          ],
        };

        const finishReason = candidate?.finishReason || "UNKNOWN";
        this.logger.info(
          `✅ [Request] OpenAI非流式响应结束，原因: ${finishReason}，请求ID: ${requestId}`
        );

        res.status(200).json(openaiResponse);
      }
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      this.connectionRegistry.removeMessageQueue(requestId);
      if (!res.writableEnded) {
        res.end();
      }
      
      // [核心] 结束处理
      this.activeRequestCount--;
      if (this.activeRequestCount < 0) this.activeRequestCount = 0;
      this._tryExecutePendingSwitch();
    }
  }

async processModelListRequest(req, res) {
  const requestId = this._generateRequestId();
  const proxyRequest = this._buildProxyRequest(req, requestId);

  proxyRequest.path = "/v1beta/models";
  proxyRequest.method = "GET";
  proxyRequest.body = null;
  proxyRequest.is_generative = false;
  proxyRequest.streaming_mode = "fake";
  proxyRequest.client_wants_stream = false;
  proxyRequest.query_params = req.query;

  this.logger.info(`[Adapter] 收到获取模型列表请求，正在转发至Google... (Request ID: ${requestId})`);
  
  const messageQueue = this.connectionRegistry.createMessageQueue(requestId);

  try {
    this._forwardRequest(proxyRequest);
    
    const headerMessage = await messageQueue.dequeue();
    if (headerMessage.event_type === "error") {
      throw new Error(headerMessage.message || "Upstream error");
    }

    let fullBody = "";
    while (true) {
      const message = await messageQueue.dequeue(60000);
      if (message.type === "STREAM_END") break;
      if (message.event_type === "chunk" && message.data) {
        fullBody += message.data;
      }
    }

    let googleModels = [];
    try {
      const googleResponse = JSON.parse(fullBody);
      googleModels = googleResponse.models || [];
    } catch (e) {
      this.logger.warn(`[Adapter] 解析模型列表JSON失败: ${e.message}`);
    }
    
    const openaiModels = googleModels.map(model => {
      const id = model.name.replace("models/", "");
      return {
        id: id,
        object: "model",
        created: Math.floor(Date.now() / 1000),
        owned_by: "google",
        permission: [],
        root: id,
        parent: null
      };
    });

    res.status(200).json({
      object: "list",
      data: openaiModels
    });
    
    this.logger.info(`[Adapter] 成功获取并返回了 ${openaiModels.length} 个模型。`);

  } catch (error) {
    this.logger.error(`[Adapter] 获取模型列表失败: ${error.message}`);
    this._sendErrorResponse(res, 500, "Failed to fetch model list.");
  } finally {
    this.connectionRegistry.removeMessageQueue(requestId);
  }
}

  _cancelBrowserRequest(requestId) {
    const connection = this.connectionRegistry.getFirstConnection();
    if (connection) {
      this.logger.info(
        `[Request] 正在向浏览器发送取消请求 #${requestId} 的指令...`
      );
      connection.send(
        JSON.stringify({
          event_type: "cancel_request",
          request_id: requestId,
        })
      );
    } else {
      this.logger.warn(
        `[Request] 无法发送取消指令：没有可用的浏览器WebSocket连接。`
      );
    }
  }

  _generateRequestId() {
    return `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  }
  _buildProxyRequest(req, requestId) {
    let finalBody = req.body;

    if (this.serverSystem.enableNativeReasoning && 
       (req.path.includes("generateContent") || req.path.includes("streamGenerateContent"))) {
        try {
            finalBody = JSON.parse(JSON.stringify(req.body));
            if (!finalBody.generationConfig) {
                finalBody.generationConfig = {};
            }
            finalBody.generationConfig.thinkingConfig = { includeThoughts: true };
            this.logger.debug(`[Request] 已为请求 ${requestId} 强制注入 Native Thinking Config。`);
        } catch(e) {
            this.logger.warn(`[Request] 尝试注入 Native Thinking Config 失败: ${e.message}`);
        }
    }

    let requestBody = "";
    if (finalBody) {
      requestBody = JSON.stringify(finalBody);
    }
    return {
      path: req.path,
      method: req.method,
      headers: req.headers,
      query_params: req.query,
      body: requestBody,
      request_id: requestId,
      streaming_mode: this.serverSystem.streamingMode,
      resume_on_prohibit: this.serverSystem.enableResume,
      resume_limit: this.serverSystem.resumeLimit
    };
  }
  _forwardRequest(proxyRequest) {
    const connection = this.connectionRegistry.getFirstConnection();
    if (connection) {
      connection.send(JSON.stringify(proxyRequest));
    } else {
      throw new Error("无法转发请求：没有可用的WebSocket连接。");
    }
  }
  _sendErrorChunkToClient(res, errorMessage) {
    const errorPayload = {
      error: {
        message: `[代理系统提示] ${errorMessage}`,
        type: "proxy_error",
        code: "proxy_error",
      },
    };
    const chunk = `data: ${JSON.stringify(errorPayload)}\n\n`;
    if (res && !res.writableEnded) {
      res.write(chunk);
      this.logger.info(`[Request] 已向客户端发送标准错误信号: ${errorMessage}`);
    }
  }

  async _handlePseudoStreamResponse(proxyRequest, messageQueue, req, res) {
    this.logger.info(
      "[Request] 客户端启用流式传输 (fake)，进入伪流式处理模式..."
    );
    res.status(200).set({
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    const connectionMaintainer = setInterval(() => {
      if (!res.writableEnded) res.write(": keep-alive\n\n");
    }, 3000);

    try {
      let lastMessage,
        requestFailed = false;

      for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
        if (attempt > 1) {
          this.logger.info(
            `[Request] 请求尝试 #${attempt}/${this.maxRetries}...`
          );
        }
        this._forwardRequest(proxyRequest);
        try {
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(
              () =>
                reject(
                  new Error("Response from browser timed out after 300 seconds")
                ),
              300000
            )
          );
          lastMessage = await Promise.race([
            messageQueue.dequeue(),
            timeoutPromise,
          ]);
        } catch (timeoutError) {
          this.logger.error(`[Request] 致命错误: ${timeoutError.message}`);
          lastMessage = {
            event_type: "error",
            status: 504,
            message: timeoutError.message,
          };
        }

        if (lastMessage.event_type === "error") {
          if (
            !(
              lastMessage.message &&
              lastMessage.message.includes("The user aborted a request")
            )
          ) {
            this.logger.warn(
              `[Request] 尝试 #${attempt} 失败: 收到 ${
                lastMessage.status || "未知"
              } 错误。 - ${lastMessage.message}`
            );
          }

          if (attempt < this.maxRetries) {
            await new Promise((resolve) =>
              setTimeout(resolve, this.retryDelay)
            );
            continue;
          }
          requestFailed = true;
        }
        break;
      }

      if (requestFailed) {
        if (
          lastMessage.message &&
          lastMessage.message.includes("The user aborted a request")
        ) {
          this.logger.info(
            `[Request] 请求 #${proxyRequest.request_id} 已由用户妥善取消，不计入失败统计。`
          );
        } else {
          this.logger.error(
            `[Request] 所有 ${this.maxRetries} 次重试均失败，将计入失败统计。`
          );
          await this._handleRequestFailureAndSwitch(lastMessage, res);
          this._sendErrorChunkToClient(
            res,
            `请求最终失败: ${lastMessage.message}`
          );
        }
        return;
      }

      if (proxyRequest.is_generative && this.failureCount > 0) {
        this.logger.info(
          `✅ [Auth] 生成请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
        );
        this.failureCount = 0;
      }
      const dataMessage = await messageQueue.dequeue();
      const endMessage = await messageQueue.dequeue();
      if (dataMessage.data) {
        res.write(`data: ${dataMessage.data}\n\n`);
      }
      if (endMessage.type !== "STREAM_END") {
        this.logger.warn("[Request] 未收到预期的流结束信号。");
      }
      try {
        const fullResponse = JSON.parse(dataMessage.data);
        const finishReason =
          fullResponse.candidates?.[0]?.finishReason || "UNKNOWN";
        this.logger.info(
          `✅ [Request] 响应结束，原因: ${finishReason}，请求ID: ${proxyRequest.request_id}`
        );
      } catch (e) {}
      res.write("data: [DONE]\n\n");
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      clearInterval(connectionMaintainer);
      if (!res.writableEnded) {
        res.end();
      }
      this.logger.info(
        `[Request] 响应处理结束，请求ID: ${proxyRequest.request_id}`
      );
    }
  }

  async _handleRealStreamResponse(proxyRequest, messageQueue, res) {
    this.logger.info(`[Request] 请求已派发给浏览器端处理...`);
    this._forwardRequest(proxyRequest);
    const headerMessage = await messageQueue.dequeue();

    if (headerMessage.event_type === "error") {
      if (
        headerMessage.message &&
        headerMessage.message.includes("The user aborted a request")
      ) {
        this.logger.info(
          `[Request] 请求 #${proxyRequest.request_id} 已被用户妥善取消，不计入失败统计。`
        );
      } else {
        this.logger.error(`[Request] 请求失败，将计入失败统计。`);
        await this._handleRequestFailureAndSwitch(headerMessage, null);
        return this._sendErrorResponse(
          res,
          headerMessage.status,
          headerMessage.message
        );
      }
      if (!res.writableEnded) res.end();
      return;
    }

    if (proxyRequest.is_generative && this.failureCount > 0) {
      this.logger.info(
        `✅ [Auth] 生成请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
      );
      this.failureCount = 0;
    }

    this._setResponseHeaders(res, headerMessage, true); 
    
    this.logger.info("[Request] 开始流式传输...");
    
    let capturedFinishReason = "UNKNOWN"; 

    try {
      let lastChunk = "";
      while (true) {
        const dataMessage = await messageQueue.dequeue(30000);
        if (dataMessage.type === "STREAM_END") {
          this.logger.info("[Request] 收到流结束信号。");
          break;
        }
        if (dataMessage.data) {
          res.write(dataMessage.data);
          
          const match = dataMessage.data.match(/"finishReason"\s*:\s*"([^"]+)"/);
          if (match && match[1]) {
              capturedFinishReason = match[1];
          }
          
          lastChunk = dataMessage.data;
        }
      }
      try {
        if (capturedFinishReason === "UNKNOWN" && lastChunk.startsWith("data: ")) {
          const jsonString = lastChunk.substring(6).trim();
          if (jsonString) {
            const lastResponse = JSON.parse(jsonString);
            capturedFinishReason = lastResponse.candidates?.[0]?.finishReason || "UNKNOWN";
          }
        }
      } catch (e) {}
      
      this.logger.info(
        `✅ [Request] 响应结束，原因: ${capturedFinishReason}，请求ID: ${proxyRequest.request_id}`
      );
      
    } catch (error) {
      if (error.message !== "Queue timeout") throw error;
      this.logger.warn("[Request] 真流式响应超时，可能流已正常结束。");
    } finally {
      if (!res.writableEnded) res.end();
      this.logger.info(
        `[Request] 真流式响应连接已关闭，请求ID: ${proxyRequest.request_id}`
      );
    }
  }

  async _handleNonStreamResponse(proxyRequest, messageQueue, res) {
    this.logger.info(`[Request] 进入非流式处理模式...`);

    this._forwardRequest(proxyRequest);

    try {
      const headerMessage = await messageQueue.dequeue();
      if (headerMessage.event_type === "error") {
        if (headerMessage.message?.includes("The user aborted a request")) {
          this.logger.info(
            `[Request] 请求 #${proxyRequest.request_id} 已被用户妥善取消。`
          );
        } else {
          this.logger.error(
            `[Request] 浏览器端返回错误: ${headerMessage.message}`
          );
          await this._handleRequestFailureAndSwitch(headerMessage, null);
        }
        return this._sendErrorResponse(
          res,
          headerMessage.status || 500,
          headerMessage.message
        );
      }

      let fullBody = "";
      while (true) {
        const message = await messageQueue.dequeue(300000);
        if (message.type === "STREAM_END") {
          this.logger.info("[Request] 收到结束信号，数据接收完毕。");
          break;
        }
        if (message.event_type === "chunk" && message.data) {
          fullBody += message.data;
        }
      }

      if (proxyRequest.is_generative && this.failureCount > 0) {
        this.logger.info(
          `✅ [Auth] 非流式生成请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
        );
        this.failureCount = 0;
      }

      try {
        let parsedBody = JSON.parse(fullBody);
        let needsReserialization = false;

        const candidate = parsedBody.candidates?.[0];
        if (candidate?.content?.parts) {
          const imagePartIndex = candidate.content.parts.findIndex(
            (p) => p.inlineData
          );

          if (imagePartIndex > -1) {
            this.logger.info(
              "[Proxy] 检测到Google格式响应中的图片数据，正在转换为Markdown..."
            );
            const imagePart = candidate.content.parts[imagePartIndex];
            const image = imagePart.inlineData;

            const markdownTextPart = {
              text: `![Generated Image](data:${image.mimeType};base64,${image.data})`,
            };

            candidate.content.parts[imagePartIndex] = markdownTextPart;
            needsReserialization = true;
          }
        }

        if (needsReserialization) {
          fullBody = JSON.stringify(parsedBody); 
        }
      } catch (e) {
        this.logger.warn(
          `[Proxy] 响应体不是有效的JSON，或在处理图片时出错: ${e.message}`
        );
      }

      try {
        const fullResponse = JSON.parse(fullBody);
        const finishReason =
          fullResponse.candidates?.[0]?.finishReason || "UNKNOWN";
        this.logger.info(
          `✅ [Request] 响应结束，原因: ${finishReason}，请求ID: ${proxyRequest.request_id}`
        );
      } catch (e) {}

      res
        .status(headerMessage.status || 200)
        .type("application/json")
        .send(fullBody || "{}");

      this.logger.info(`[Request] 已向客户端发送完整的非流式响应。`);
    } catch (error) {
      this._handleRequestError(error, res);
    }
  }

  _getKeepAliveChunk(req) {
    if (req.path.includes("chat/completions")) {
      const payload = {
        id: `chatcmpl-${this._generateRequestId()}`,
        object: "chat.completion.chunk",
        created: Math.floor(Date.now() / 1000),
        model: "gpt-4",
        choices: [{ index: 0, delta: {}, finish_reason: null }],
      };
      return `data: ${JSON.stringify(payload)}\n\n`;
    }
    if (
      req.path.includes("generateContent") ||
      req.path.includes("streamGenerateContent")
    ) {
      const payload = {
        candidates: [
          {
            content: { parts: [{ text: "" }], role: "model" },
            finishReason: null,
            index: 0,
            safetyRatings: [],
          },
        ],
      };
      return `data: ${JSON.stringify(payload)}\n\n`;
    }
    return "data: {}\n\n";
  }

  _setResponseHeaders(res, headerMessage, isStream = false) {
    res.status(headerMessage.status || 200);
    const headers = headerMessage.headers || {};
    Object.entries(headers).forEach(([name, value]) => {
      if (name.toLowerCase() === "content-length") return;
      if (isStream && name.toLowerCase() === "content-type") return;
      res.set(name, value);
    });

    if (isStream) {
        res.set("Content-Type", "text/event-stream");
        res.set("Cache-Control", "no-cache");
        res.set("Connection", "keep-alive");
    }
  }
  
  _handleRequestError(error, res) {
    if (res.headersSent) {
      this.logger.error(`[Request] 请求处理错误 (头已发送): ${error.message}`);
      if (this.serverSystem.streamingMode === "fake")
        this._sendErrorChunkToClient(res, `处理失败: ${error.message}`);
      if (!res.writableEnded) res.end();
    } else {
      this.logger.error(`[Request] 请求处理错误: ${error.message}`);
      const status = error.message.includes("超时") ? 504 : 500;
      this._sendErrorResponse(res, status, `代理错误: ${error.message}`);
    }
  }

  _sendErrorResponse(res, status, message) {
    if (!res.headersSent) {
      const errorPayload = {
        error: {
          code: status || 500,
          message: message,
          status: "SERVICE_UNAVAILABLE",
        },
      };
      res
        .status(status || 500)
        .type("application/json")
        .send(JSON.stringify(errorPayload));
    }
  }

  _translateOpenAIToGoogle(openaiBody, modelName = "") {
    this.logger.info("[Adapter] 开始将OpenAI请求格式翻译为Google格式...");

    let systemInstruction = null;
    const googleContents = [];

    const systemMessages = openaiBody.messages.filter(
      (msg) => msg.role === "system"
    );
    if (systemMessages.length > 0) {
      const systemContent = systemMessages.map((msg) => msg.content).join("\n");
      systemInstruction = {
        role: "system",
        parts: [{ text: systemContent }],
      };
    }

    const conversationMessages = openaiBody.messages.filter(
      (msg) => msg.role !== "system"
    );
    for (const message of conversationMessages) {
      const googleParts = [];

      if (typeof message.content === "string") {
        googleParts.push({ text: message.content });
      } else if (Array.isArray(message.content)) {
        for (const part of message.content) {
          if (part.type === "text") {
            googleParts.push({ text: part.text });
          } else if (part.type === "image_url" && part.image_url) {
            const dataUrl = part.image_url.url;
            const match = dataUrl.match(/^data:(image\/.*?);base64,(.*)$/);
            if (match) {
              googleParts.push({
                inlineData: {
                  mimeType: match[1],
                  data: match[2],
                },
              });
            }
          }
        }
      }

      googleContents.push({
        role: message.role === "assistant" ? "model" : "user",
        parts: googleParts,
      });
    }

    const googleRequest = {
      contents: googleContents,
      ...(systemInstruction && {
        systemInstruction: { parts: systemInstruction.parts },
      }),
    };

    const generationConfig = {
      temperature: openaiBody.temperature,
      topP: openaiBody.top_p,
      topK: openaiBody.top_k,
      maxOutputTokens: openaiBody.max_tokens,
      stopSequences: openaiBody.stop,
    };
    
    if (this.serverSystem.enableReasoning) {
        this.logger.info("[Adapter] 检测到推理模式已启用，正在注入 thinkingConfig...");
        generationConfig.thinkingConfig = { includeThoughts: true };
    }
    
    googleRequest.generationConfig = generationConfig;

    googleRequest.safetySettings = [
      { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
    ];

    this.logger.info("[Adapter] 翻译完成。");
    return googleRequest;
  }

  _translateGoogleToOpenAIStream(googleChunk, modelName = "gemini-pro") {
    if (!googleChunk || googleChunk.trim() === "") {
      return null;
    }

    let jsonString = googleChunk;
    if (jsonString.startsWith("data: ")) {
      jsonString = jsonString.substring(6).trim();
    }

    if (!jsonString || jsonString === "[DONE]") return null;

    let googleResponse;
    try {
      googleResponse = JSON.parse(jsonString);
    } catch (e) {
      this.logger.warn(`[Adapter] 无法解析Google返回的JSON块: ${jsonString}`);
      return null;
    }

    const candidate = googleResponse.candidates?.[0];
    if (!candidate) {
      if (googleResponse.promptFeedback) {
        this.logger.warn(
          `[Adapter] Google返回了promptFeedback，可能已被拦截: ${JSON.stringify(
            googleResponse.promptFeedback
          )}`
        );
        const errorText = `[ProxySystem Error] Request blocked due to safety settings. Finish Reason: ${googleResponse.promptFeedback.blockReason}`;
        return `data: ${JSON.stringify({
          id: `chatcmpl-${this._generateRequestId()}`,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model: modelName,
          choices: [
            { index: 0, delta: { content: errorText }, finish_reason: "stop" },
          ],
        })}\n\n`;
      }
      return null;
    }

    let content = "";
    let reasoningContent = "";

    if (candidate.content && Array.isArray(candidate.content.parts)) {
      candidate.content.parts.forEach((p) => {
        if (p.inlineData) {
            const image = p.inlineData;
            content += `![Generated Image](data:${image.mimeType};base64,${image.data})`;
            this.logger.info("[Adapter] 从流式响应块中成功解析到图片。");
        } else if (p.thought) {
            reasoningContent += p.text || "";
        } else {
            content += p.text || "";
        }
      });
    }

    const finishReason = candidate.finishReason;
    const delta = {};
    
    if (content) delta.content = content;
    if (reasoningContent) delta.reasoning_content = reasoningContent;

    if (Object.keys(delta).length === 0 && !finishReason) {
        return null;
    }

    const openaiResponse = {
      id: `chatcmpl-${this._generateRequestId()}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: modelName,
      choices: [
        {
          index: 0,
          delta: delta,
          finish_reason: finishReason || null,
        },
      ],
    };

    return `data: ${JSON.stringify(openaiResponse)}\n\n`;
  }
}

class ProxyServerSystem extends EventEmitter {
  constructor() {
    super();
    this.logger = new LoggingService("ProxySystem");
    this._loadConfiguration(); 
    this.streamingMode = this.config.streamingMode;
    
    // [新增] 默认为 false，用户可通过面板开启
    this.enableReasoning = false; 
    // [新增] 强制开启原生格式推理
    this.enableNativeReasoning = false;
    
    // [新增] 续写开关和限制
    this.enableResume = false; 
    this.resumeLimit = 3; // 默认最大重试3次

    this.authSource = new AuthSource(this.logger);
    this.browserManager = new BrowserManager(
      this.logger,
      this.config,
      this.authSource
    );
    this.connectionRegistry = new ConnectionRegistry(this.logger);
    this.requestHandler = new RequestHandler(
      this,
      this.connectionRegistry,
      this.logger,
      this.browserManager,
      this.config,
      this.authSource
    );

    this.httpServer = null;
    this.wsServer = null;
  }

  _loadConfiguration() {
    // ... [Config loading logic unchanged] ...
    let config = {
      httpPort: 7860,
      host: "0.0.0.0",
      wsPort: 9998,
      streamingMode: "real",
      failureThreshold: 3,
      switchOnUses: 40,
      maxRetries: 1,
      retryDelay: 2000,
      browserExecutablePath: null,
      apiKeys: [],
      immediateSwitchStatusCodes: [429, 503],
      apiKeySource: "未设置",
    };

    if (process.env.PORT)
      config.httpPort = parseInt(process.env.PORT, 10) || config.httpPort;
    if (process.env.HOST) config.host = process.env.HOST;
    if (process.env.STREAMING_MODE)
      config.streamingMode = process.env.STREAMING_MODE;
    if (process.env.FAILURE_THRESHOLD)
      config.failureThreshold =
        parseInt(process.env.FAILURE_THRESHOLD, 10) || config.failureThreshold;
    if (process.env.SWITCH_ON_USES)
      config.switchOnUses =
        parseInt(process.env.SWITCH_ON_USES, 10) || config.switchOnUses;
    if (process.env.MAX_RETRIES)
      config.maxRetries =
        parseInt(process.env.MAX_RETRIES, 10) || config.maxRetries;
    if (process.env.RETRY_DELAY)
      config.retryDelay =
        parseInt(process.env.RETRY_DELAY, 10) || config.retryDelay;
    if (process.env.CAMOUFOX_EXECUTABLE_PATH)
      config.browserExecutablePath = process.env.CAMOUFOX_EXECUTABLE_PATH;
    if (process.env.API_KEYS) {
      config.apiKeys = process.env.API_KEYS.split(",");
    }

    let rawCodes = process.env.IMMEDIATE_SWITCH_STATUS_CODES;
    let codesSource = "环境变量";

    if (
      !rawCodes &&
      config.immediateSwitchStatusCodes &&
      Array.isArray(config.immediateSwitchStatusCodes)
    ) {
      rawCodes = config.immediateSwitchStatusCodes.join(",");
      codesSource = "系统默认值";
    }

    if (rawCodes && typeof rawCodes === "string") {
      config.immediateSwitchStatusCodes = rawCodes
        .split(",")
        .map((code) => parseInt(String(code).trim(), 10))
        .filter((code) => !isNaN(code) && code >= 400 && code <= 599);
      if (config.immediateSwitchStatusCodes.length > 0) {
        this.logger.info(`[System] 已从 ${codesSource} 加载“立即切换报错码”。`);
      }
    } else {
      config.immediateSwitchStatusCodes = [];
    }

    if (Array.isArray(config.apiKeys)) {
      config.apiKeys = config.apiKeys
        .map((k) => String(k).trim())
        .filter((k) => k);
    } else {
      config.apiKeys = [];
    }

    if (config.apiKeys.length > 0) {
      config.apiKeySource = "自定义";
    } else {
      config.apiKeys = ["123456"];
      config.apiKeySource = "默认";
      this.logger.info("[System] 未设置任何API Key，已启用默认密码: 123456");
    }
    
    this.config = config;
    this.logger.info("================ [ 生效配置 ] ================");
    this.logger.info(`  HTTP 服务端口: ${this.config.httpPort}`);
    this.logger.info(`  监听地址: ${this.config.host}`);
    this.logger.info(`  流式模式: ${this.config.streamingMode}`);
    this.logger.info(
      `  轮换计数切换阈值: ${
        this.config.switchOnUses > 0
          ? `每 ${this.config.switchOnUses} 次请求后切换`
          : "已禁用"
      }`
    );
    this.logger.info(
      `  失败计数切换: ${
        this.config.failureThreshold > 0
          ? `失败${this.config.failureThreshold} 次后切换`
          : "已禁用"
      }`
    );
    this.logger.info(
      `  立即切换报错码: ${
        this.config.immediateSwitchStatusCodes.length > 0
          ? this.config.immediateSwitchStatusCodes.join(", ")
          : "已禁用"
      }`
    );
    this.logger.info(`  单次请求最大重试: ${this.config.maxRetries}次`);
    this.logger.info(`  重试间隔: ${this.config.retryDelay}ms`);
    this.logger.info(`  API 密钥来源: ${this.config.apiKeySource}`); 
    this.logger.info(
      "============================================================="
    );
  }

  async start(initialAuthIndex = null) {
    // ... [Start logic unchanged] ...
    this.logger.info("[System] 开始弹性启动流程...");
    const allAvailableIndices = this.authSource.availableIndices;

    if (allAvailableIndices.length === 0) {
      throw new Error("没有任何可用的认证源，无法启动。");
    }

    let startupOrder = [...allAvailableIndices];
    if (initialAuthIndex && allAvailableIndices.includes(initialAuthIndex)) {
      this.logger.info(
        `[System] 检测到指定启动索引 #${initialAuthIndex}，将优先尝试。`
      );
      startupOrder = [
        initialAuthIndex,
        ...allAvailableIndices.filter((i) => i !== initialAuthIndex),
      ];
    } else {
      if (initialAuthIndex) {
        this.logger.warn(
          `[System] 指定的启动索引 #${initialAuthIndex} 无效或不可用，将按默认顺序启动。`
        );
      }
      this.logger.info(
        `[System] 未指定有效启动索引，将按默认顺序 [${startupOrder.join(
          ", "
        )}] 尝试。`
      );
    }

    let isStarted = false;
    for (const index of startupOrder) {
      try {
        this.logger.info(`[System] 尝试使用账号 #${index} 启动服务...`);
        await this.browserManager.launchOrSwitchContext(index);

        isStarted = true;
        this.logger.info(`[System] ✅ 使用账号 #${index} 成功启动！`);
        break; 
      } catch (error) {
        this.logger.error(
          `[System] ❌ 使用账号 #${index} 启动失败。原因: ${error.message}`
        );
      }
    }

    if (!isStarted) {
      throw new Error("所有认证源均尝试失败，服务器无法启动。");
    }

    await this._startHttpServer();
    await this._startWebSocketServer();
    this.logger.info(`[System] 代理服务器系统启动完成。`);
    this.emit("started");
  }

  _createAuthMiddleware() {
     // ... [Auth middleware unchanged] ...
    const basicAuth = require("basic-auth"); 

    return (req, res, next) => {
      const serverApiKeys = this.config.apiKeys;
      if (!serverApiKeys || serverApiKeys.length === 0) {
        return next();
      }

      let clientKey = null;
      if (req.headers["x-goog-api-key"]) {
        clientKey = req.headers["x-goog-api-key"];
      } else if (
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer ")
      ) {
        clientKey = req.headers.authorization.substring(7);
      } else if (req.headers["x-api-key"]) {
        clientKey = req.headers["x-api-key"];
      } else if (req.query.key) {
        clientKey = req.query.key;
      }

      if (clientKey && serverApiKeys.includes(clientKey)) {
        if (req.query.key) {
          delete req.query.key;
        }
        return next();
      }

      if (req.path !== "/favicon.ico") {
        const clientIp = req.headers["x-forwarded-for"] || req.ip;
        this.logger.warn(
          `[Auth] 访问密码错误或缺失，已拒绝请求。IP: ${clientIp}, Path: ${req.path}`
        );
      }

      return res.status(401).json({
        error: {
          message:
            "Access denied. A valid API key was not found or is incorrect.",
        },
      });
    };
  }

  async _startHttpServer() {
    // ... [Server creation unchanged] ...
    const app = this._createExpressApp();
    this.httpServer = http.createServer(app);

    this.httpServer.keepAliveTimeout = 120000;
    this.httpServer.headersTimeout = 125000;
    this.httpServer.requestTimeout = 120000;

    return new Promise((resolve) => {
      this.httpServer.listen(this.config.httpPort, this.config.host, () => {
        this.logger.info(
          `[System] HTTP服务器已在 http://${this.config.host}:${this.config.httpPort} 上监听`
        );
        this.logger.info(
          `[System] Keep-Alive 超时已设置为 ${
            this.httpServer.keepAliveTimeout / 1000
          } 秒。`
        );
        resolve();
      });
    });
  }

  _createExpressApp() {
    const app = express();

    app.use((req, res, next) => {
      res.header("Access-Control-Allow-Origin", "*");
      res.header(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, PATCH, OPTIONS"
      );
      res.header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, x-requested-with, x-api-key, x-goog-api-key, origin, accept"
      );
      if (req.method === "OPTIONS") {
        return res.sendStatus(204);
      }
      next();
    });

    app.use((req, res, next) => {
      if (
        req.path !== "/api/status" &&
        req.path !== "/" &&
        req.path !== "/favicon.ico" &&
        req.path !== "/login"
      ) {
        this.logger.info(
          `[Entrypoint] 收到一个请求: ${req.method} ${req.path}`
        );
      }
      next();
    });
    app.use(express.json({ limit: "100mb" }));
    app.use(express.urlencoded({ extended: true }));

    const sessionSecret =
      (this.config.apiKeys && this.config.apiKeys[0]) ||
      crypto.randomBytes(20).toString("hex");
    app.use(cookieParser());
    app.use(
      session({
        secret: sessionSecret,
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false, maxAge: 86400000 },
      })
    );
    const isAuthenticated = (req, res, next) => {
      if (req.session.isAuthenticated) {
        return next();
      }
      res.redirect("/login");
    };
    // ... [Login HTML/Route unchanged] ...
    app.get("/login", (req, res) => {
  if (req.session.isAuthenticated) {
    return res.redirect("/");
  }
  const loginHtml = `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>登录</title>
    <style>
      * { box-sizing: border-box; }
      html, body {
        height: 100%;
        width: 100%;
        margin: 0;
        padding: 0;
        overflow: hidden;
        background: #f0f2f5;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      }
      
      .container {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center; 
        overflow-y: auto;
        -webkit-overflow-scrolling: touch;
        padding-bottom: 20vh; /* 视觉重心上移 */
      }

      @media (max-height: 500px) {
        .container {
          padding-bottom: 0;
          justify-content: flex-start;
          padding-top: 20px;
        }
      }

      form {
        background: white;
        padding: 30px 25px;
        border-radius: 16px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.08);
        text-align: center;
        width: 85%;
        max-width: 360px;
        flex-shrink: 0;
        transition: transform 0.3s ease;
      }

      h2 {
        margin-top: 0;
        margin-bottom: 25px;
        font-size: 1.3rem;
        color: #333;
        font-weight: 600;
      }

      .input-wrapper {
        position: relative;
        width: 100%;
        margin-bottom: 15px;
      }

      input {
        width: 100%;
        padding: 14px;
        padding-right: 45px; 
        border: 1px solid #ddd;
        border-radius: 10px;
        font-size: 16px;
        outline: none;
        background: #f9f9f9;
        -webkit-appearance: none;
        transition: all 0.2s;
        margin-bottom: 0; 
      }
      
      input:focus {
        background: #fff;
        border-color: #007bff;
        box-shadow: 0 0 0 3px rgba(0,123,255,0.1);
      }

      .toggle-eye {
        position: absolute;
        right: 12px;
        top: 50%;
        transform: translateY(-50%);
        cursor: pointer;
        color: #999;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
        -webkit-tap-highlight-color: transparent;
        z-index: 10;
      }

      .toggle-eye svg {
        width: 20px;
        height: 20px;
        fill: none;
        stroke: currentColor;
        stroke-width: 2;
        stroke-linecap: round;
        stroke-linejoin: round;
      }

      button {
        width: 100%;
        padding: 14px;
        background-color: #007bff;
        color: white;
        border: none;
        border-radius: 10px;
        cursor: pointer;
        font-size: 16px;
        font-weight: bold;
        -webkit-tap-highlight-color: transparent;
        box-shadow: 0 4px 6px rgba(0,123,255,0.2);
      }
      
      button:active {
        background-color: #0056b3;
        transform: scale(0.98);
      }

      .error {
        color: #dc3545;
        margin-top: 15px;
        font-size: 14px;
        background: #fff5f5;
        padding: 8px;
        border-radius: 6px;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <form action="/login" method="post">
        <h2>API Key 验证</h2>
        
        <div class="input-wrapper">
            <input type="password" id="apiKeyInput" name="apiKey" placeholder="请输入 API Key" required autofocus autocomplete="off">
            <div class="toggle-eye" id="toggleBtn">
                <svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            </div>
        </div>

        <button type="submit">进入系统</button>
        ${req.query.error ? '<div class="error">验证失败，请重试</div>' : ""}
      </form>
    </div>

    <script>
      const input = document.getElementById('apiKeyInput');
      const toggleBtn = document.getElementById('toggleBtn');
      
      const eyeOpen = '<svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
      const eyeClosed = '<svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';

      toggleBtn.innerHTML = eyeClosed;

      toggleBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
        input.setAttribute('type', type);
        if (type === 'text') {
            toggleBtn.innerHTML = eyeOpen;
            toggleBtn.style.color = '#007bff'; 
        } else {
            toggleBtn.innerHTML = eyeClosed;
            toggleBtn.style.color = '#999';
        }
      });

      const container = document.querySelector('.container');
      input.addEventListener('focus', () => {
        setTimeout(() => {
          input.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 300);
      });

      document.body.addEventListener('touchmove', function(e) {
        if (!e.target.closest('.container')) {
          e.preventDefault();
        }
      }, { passive: false });
    </script>
  </body>
  </html>`;
  res.send(loginHtml);
});
    app.post("/login", (req, res) => {
      const { apiKey } = req.body;
      if (apiKey && this.config.apiKeys.includes(apiKey)) {
        req.session.isAuthenticated = true;
        res.redirect("/");
      } else {
        res.redirect("/login?error=1");
      }
    });

    // ==========================================================
    // Section 3: 状态页面 (已添加推理模式显示与按钮)
    // ==========================================================
    app.get("/", isAuthenticated, (req, res) => {
      const { config, requestHandler, authSource, browserManager } = this;
      const initialIndices = authSource.initialIndices || [];
      const availableIndices = authSource.availableIndices || [];
      const invalidIndices = initialIndices.filter(
        (i) => !availableIndices.includes(i)
      );
      const logs = this.logger.logBuffer || [];

      const accountNameMap = authSource.accountNameMap;
      const accountDetailsHtml = initialIndices
        .map((index) => {
          const isInvalid = invalidIndices.includes(index);
          const name = isInvalid
            ? "N/A (JSON格式错误)"
            : accountNameMap.get(index) || "N/A (未命名)";
          return `<span class="label" style="padding-left: 20px;">账号${index}</span>: ${name}`;
        })
        .join("\n");

      const accountOptionsHtml = availableIndices
        .map((index) => `<option value="${index}">账号 #${index}</option>`)
        .join("");

      const statusHtml = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>代理服务状态</title>
        <style>
        body { font-family: 'SF Mono', 'Consolas', 'Menlo', monospace; background-color: #f0f2f5; color: #333; padding: 2em; }
        .container { max-width: 800px; margin: 0 auto; background: #fff; padding: 1em 2em 2em 2em; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 0.5em;}
        pre { background: #2d2d2d; color: #f0f0f0; font-size: 1.1em; padding: 1.5em; border-radius: 8px; white-space: pre-wrap; word-wrap: break-word; line-height: 1.6; }
        #log-container { font-size: 0.9em; max-height: 400px; overflow-y: auto; }
        .status-ok { color: #2ecc71; font-weight: bold; }
        .status-error { color: #e74c3c; font-weight: bold; }
        .status-info { color: #3498db; font-weight: bold; }
        .label { display: inline-block; width: 220px; box-sizing: border-box; }
        .dot { height: 10px; width: 10px; background-color: #bbb; border-radius: 50%; display: inline-block; margin-left: 10px; animation: blink 1s infinite alternate; }
        @keyframes blink { from { opacity: 0.3; } to { opacity: 1; } }
        .action-group { display: flex; flex-wrap: wrap; gap: 15px; align-items: center; }
        .action-group button, .action-group select { font-size: 1em; border: 1px solid #ccc; padding: 10px 15px; border-radius: 8px; cursor: pointer; transition: background-color 0.3s ease; }
        .action-group button:hover { opacity: 0.85; }
        /* [修改] 所有按钮统一为蓝色 */
        .action-group button { background-color: #007bff; color: white; border-color: #007bff; }
        .action-group button.warning-btn { background-color: #007bff; border-color: #007bff; }
        .action-group button.purple-btn { background-color: #007bff; border-color: #007bff; }
        .action-group select { background-color: #ffffff; color: #000000; -webkit-appearance: none; appearance: none; }
        @media (max-width: 600px) {
            body { padding: 0.5em; }
            .container { padding: 1em; margin: 0; }
            pre { padding: 1em; font-size: 0.9em; }
            .label { width: auto; display: inline; }
            .action-group { flex-direction: column; align-items: stretch; }
            .action-group select, .action-group button { width: 100%; box-sizing: border-box; }
        }
        </style>
    </head>
    <body>
        <div class="container">
        <h1>代理服务状态 <span class="dot" title="数据动态刷新中..."></span></h1>
        <div id="status-section">
            <pre>
<span class="label">服务状态</span>: <span class="status-ok">Running</span>
<span class="label">浏览器连接</span>: <span class="${
        browserManager.browser ? "status-ok" : "status-error"
      }">${!!browserManager.browser}</span>
--- 服务配置 ---
<span class="label">流模式</span>: ${config.streamingMode} (仅启用流式传输时生效)
<span class="label">强制OAI格式推理 (OAI)</span>: <span class="${this.enableReasoning ? "status-info" : ""}">${this.enableReasoning ? "已启用 (注入thinkingConfig)" : "已禁用"}</span>
<span class="label">强制原生格式推理 (Native)</span>: <span class="${this.enableNativeReasoning ? "status-info" : ""}">${this.enableNativeReasoning ? "已启用 (注入thinkingConfig)" : "已禁用"}</span>
<span class="label">截断自动续写</span>: <span class="${this.enableResume ? "status-info" : ""}">${this.enableResume ? "已启用 (Limit: " + this.resumeLimit + ")" : "已禁用"}</span>
<span class="label">立即切换 (状态码)</span>: ${
        config.immediateSwitchStatusCodes.length > 0
          ? `[${config.immediateSwitchStatusCodes.join(", ")}]`
          : "已禁用"
      }
<span class="label">API 密钥</span>: ${config.apiKeySource}
--- 账号状态 ---
<span class="label">当前使用账号</span>: #${requestHandler.currentAuthIndex}
<span class="label">使用次数计数</span>: ${requestHandler.usageCount} / ${
        config.switchOnUses > 0 ? config.switchOnUses : "N/A"
      }
<span class="label">连续失败计数</span>: ${requestHandler.failureCount} / ${
        config.failureThreshold > 0 ? config.failureThreshold : "N/A"
      }
<span class="label">扫描到的总帐号</span>: [${initialIndices.join(
        ", "
      )}] (总数: ${initialIndices.length})
      ${accountDetailsHtml}
<span class="label">格式错误 (已忽略)</span>: [${invalidIndices.join(
        ", "
      )}] (总数: ${invalidIndices.length})
            </pre>
        </div>
        <div id="log-section" style="margin-top: 2em;">
            <h2>实时日志 (最近 ${logs.length} 条)</h2>
            <pre id="log-container">${logs.join("\n")}</pre>
        </div>
        <div id="actions-section" style="margin-top: 2em;">
            <h2>操作面板</h2>
            <div class="action-group">
                <select id="accountIndexSelect">${accountOptionsHtml}</select>
                <button onclick="switchSpecificAccount()">切换账号</button>
                <button onclick="toggleStreamingMode()">切换流模式</button>
                <!-- [修改] 移除了内联样式，统一使用 CSS 蓝色 -->
                <button class="warning-btn" onclick="toggleReasoning()">强制开启OAI格式推理</button>
                <button class="warning-btn" onclick="toggleNativeReasoning()">强制开启原生格式推理</button>
                <button class="purple-btn" onclick="configureResume()">设置截断自动续写</button>
            </div>
        </div>
        </div>
        <script>
        let currentResumeLimit = 3;

        function updateContent() {
            fetch('/api/status').then(response => response.json()).then(data => {
                const statusPre = document.querySelector('#status-section pre');
                const accountDetailsHtml = data.status.accountDetails.map(acc => {
                  return '<span class="label" style="padding-left: 20px;">账号' + acc.index + '</span>: ' + acc.name;
                }).join('\\n');
                
                const reasoningClass = data.status.enableReasoning ? "status-info" : "";
                const reasoningText = data.status.enableReasoning ? "已启用 (注入thinkingConfig)" : "已禁用";
                
                const nativeReasoningClass = data.status.enableNativeReasoning ? "status-info" : "";
                const nativeReasoningText = data.status.enableNativeReasoning ? "已启用 (注入thinkingConfig)" : "已禁用";
                
                const resumeClass = data.status.enableResume ? "status-info" : "";
                const resumeText = data.status.enableResume ? ("已启用 (Limit: " + data.status.resumeLimit + ")") : "已禁用";
                
                currentResumeLimit = data.status.resumeLimit;

                statusPre.innerHTML = 
                    '<span class="label">服务状态</span>: <span class="status-ok">Running</span>\\n' +
                    '<span class="label">浏览器连接</span>: <span class="' + (data.status.browserConnected ? "status-ok" : "status-error") + '">' + data.status.browserConnected + '</span>\\n' +
                    '--- 服务配置 ---\\n' +
                    '<span class="label">流模式</span>: ' + data.status.streamingMode + '\\n' +
                    '<span class="label">强制OAI格式推理 (OAI)</span>: <span class="' + reasoningClass + '">' + reasoningText + '</span>\\n' +
                    '<span class="label">强制原生格式推理 (Native)</span>: <span class="' + nativeReasoningClass + '">' + nativeReasoningText + '</span>\\n' +
                    '<span class="label">截断自动续写</span>: <span class="' + resumeClass + '">' + resumeText + '</span>\\n' +
                    '<span class="label">立即切换 (状态码)</span>: ' + data.status.immediateSwitchStatusCodes + '\\n' +
                    '<span class="label">API 密钥</span>: ' + data.status.apiKeySource + '\\n' +
                    '--- 账号状态 ---\\n' +
                    '<span class="label">当前使用账号</span>: #' + data.status.currentAuthIndex + '\\n' +
                    '<span class="label">使用次数计数</span>: ' + data.status.usageCount + '\\n' +
                    '<span class="label">连续失败计数</span>: ' + data.status.failureCount + '\\n' +
                    '<span class="label">扫描到的总账号</span>: ' + data.status.initialIndices + '\\n' +
                    accountDetailsHtml + '\\n' +
                    '<span class="label">格式错误 (已忽略)</span>: ' + data.status.invalidIndices;
                
                const logContainer = document.getElementById('log-container');
                const logTitle = document.querySelector('#log-section h2');
                const isScrolledToBottom = logContainer.scrollHeight - logContainer.clientHeight <= logContainer.scrollTop + 1;
                logTitle.innerText = \`实时日志 (最近 \${data.logCount} 条)\`;
                logContainer.innerText = data.logs;
                if (isScrolledToBottom) { logContainer.scrollTop = logContainer.scrollHeight; }
            }).catch(error => console.error('Error fetching new content:', error));
        }

        function switchSpecificAccount() {
            const selectElement = document.getElementById('accountIndexSelect');
            const targetIndex = selectElement.value;
            if (!confirm(\`确定要切换到账号 #\${targetIndex} 吗？这会重置浏览器会话。\`)) {
                return;
            }
            fetch('/api/switch-account', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targetIndex: parseInt(targetIndex, 10) })
            })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => { 
                if (err.message.includes('Load failed') || err.message.includes('NetworkError')) {
                    alert('⚠️ 浏览器启动较慢，操作仍在后台进行中。\\n\\n请不要重复点击。');
                } else {
                    alert('❌ 操作失败: ' + err); 
                }
                updateContent(); 
            });
        }

        function toggleStreamingMode() { 
            const newMode = prompt('请输入新的流模式 (real 或 fake):', '${this.config.streamingMode}');
            if (newMode === 'fake' || newMode === 'real') {
                fetch('/api/set-mode', { 
                    method: 'POST', 
                    headers: { 'Content-Type': 'application/json' }, 
                    body: JSON.stringify({ mode: newMode }) 
                })
                .then(res => res.text()).then(data => { alert(data); updateContent(); })
                .catch(err => alert('设置失败: ' + err));
            } else if (newMode !== null) { 
                alert('无效的模式！请只输入 "real" 或 "fake"。'); 
            } 
        }

        function toggleReasoning() {
             fetch('/api/toggle-reasoning', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}) 
             })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => alert('切换失败: ' + err));
        }

        function toggleNativeReasoning() {
             fetch('/api/toggle-native-reasoning', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}) 
             })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => alert('切换失败: ' + err));
        }

        function configureResume() {
            const input = prompt("请输入最大重试次数 (默认为 3)\\n输入 0 即代表关闭此功能:", currentResumeLimit);
            if (input === null) return; 
            const limit = parseInt(input, 10);
            if (isNaN(limit) || limit < 0) {
                alert("请输入有效的正整数 (>=0)");
                return;
            }
            
            fetch('/api/set-resume-config', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ limit: limit }) 
            })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => alert('设置失败: ' + err));
        }

        document.addEventListener('DOMContentLoaded', () => {
            updateContent(); 
            setInterval(updateContent, 5000);
        });
        </script>
    </body>
    </html>
    `;
      res.status(200).send(statusHtml);
    });

    app.get("/api/status", isAuthenticated, (req, res) => {
      const { config, requestHandler, authSource, browserManager } = this;
      const initialIndices = authSource.initialIndices || [];
      const invalidIndices = initialIndices.filter(
        (i) => !authSource.availableIndices.includes(i)
      );
      const logs = this.logger.logBuffer || [];
      const accountNameMap = authSource.accountNameMap;
      const accountDetails = initialIndices.map((index) => {
        const isInvalid = invalidIndices.includes(index);
        const name = isInvalid
          ? "N/A (JSON格式错误)"
          : accountNameMap.get(index) || "N/A (未命名)";
        return { index, name };
      });

      const data = {
        status: {
          streamingMode: `${this.streamingMode} (仅启用流式传输时生效)`,
          // [新增] 返回推理模式状态
          enableReasoning: this.enableReasoning, 
          // [新增] 返回原生推理模式状态
          enableNativeReasoning: this.enableNativeReasoning,
          // [新增] 返回续写状态
          enableResume: this.enableResume,
          resumeLimit: this.resumeLimit, // [新增] 返回次数限制
          browserConnected: !!browserManager.browser,
          immediateSwitchStatusCodes:
            config.immediateSwitchStatusCodes.length > 0
              ? `[${config.immediateSwitchStatusCodes.join(", ")}]`
              : "已禁用",
          apiKeySource: config.apiKeySource,
          currentAuthIndex: requestHandler.currentAuthIndex,
          usageCount: `${requestHandler.usageCount} / ${
            config.switchOnUses > 0 ? config.switchOnUses : "N/A"
          }`,
          failureCount: `${requestHandler.failureCount} / ${
            config.failureThreshold > 0 ? config.failureThreshold : "N/A"
          }`,
          initialIndices: `[${initialIndices.join(", ")}] (总数: ${
            initialIndices.length
          })`,
          accountDetails: accountDetails,
          invalidIndices: `[${invalidIndices.join(", ")}] (总数: ${
            invalidIndices.length
          })`,
        },
        logs: logs.join("\n"),
        logCount: logs.length,
      };
      res.json(data);
    });
    app.post("/api/switch-account", isAuthenticated, async (req, res) => {
      try {
        const { targetIndex } = req.body;
        if (targetIndex !== undefined && targetIndex !== null) {
          this.logger.info(
            `[WebUI] 收到切换到指定账号 #${targetIndex} 的请求...`
          );
          const result = await this.requestHandler._switchToSpecificAuth(
            targetIndex
          );
          if (result.success) {
            res.status(200).send(`切换成功！已激活账号 #${result.newIndex}。`);
          } else {
            res.status(400).send(result.reason);
          }
        } else {
          this.logger.info("[WebUI] 收到手动切换下一个账号的请求...");
          if (this.authSource.availableIndices.length <= 1) {
            return res
              .status(400)
              .send("切换操作已取消：只有一个可用账号，无法切换。");
          }
          const result = await this.requestHandler._switchToNextAuth();
          if (result.success) {
            res
              .status(200)
              .send(`切换成功！已切换到账号 #${result.newIndex}。`);
          } else if (result.fallback) {
            res
              .status(200)
              .send(`切换失败，但已成功回退到账号 #${result.newIndex}。`);
          } else {
            res.status(409).send(`操作未执行: ${result.reason}`);
          }
        }
      } catch (error) {
        res
          .status(500)
          .send(`致命错误：操作失败！请检查日志。错误: ${error.message}`);
      }
    });
    app.post("/api/set-mode", isAuthenticated, (req, res) => {
      const newMode = req.body.mode;
      if (newMode === "fake" || newMode === "real") {
        this.streamingMode = newMode;
        this.logger.info(
          `[WebUI] 流式模式已由认证用户切换为: ${this.streamingMode}`
        );
        res.status(200).send(`流式模式已切换为: ${this.streamingMode}`);
      } else {
        res.status(400).send('无效模式. 请用 "fake" 或 "real".');
      }
    });
    
    // ==========================================================
    // [新增] 切换推理模式 (Toggle Reasoning) 接口 - 适配 OAI
    // ==========================================================
    app.post("/api/toggle-reasoning", isAuthenticated, (req, res) => {
      this.enableReasoning = !this.enableReasoning;
      const statusText = this.enableReasoning ? "已启用" : "已禁用";
      this.logger.info(`[WebUI] 强制OAI格式推理 (Thinking) 状态已切换为: ${statusText}`);
      res.status(200).send(`强制OAI格式推理(Thinking)${statusText}。所有新的 OpenAI 格式请求都将受此影响。`);
    });

    // ==========================================================
    // [新增] 切换原生推理模式 (Toggle Native Reasoning) 接口
    // ==========================================================
    app.post("/api/toggle-native-reasoning", isAuthenticated, (req, res) => {
      this.enableNativeReasoning = !this.enableNativeReasoning;
      const statusText = this.enableNativeReasoning ? "已启用" : "已禁用";
      this.logger.info(`[WebUI] 强制原生格式推理 (Native Thinking) 状态已切换为: ${statusText}`);
      res.status(200).send(`强制原生格式推理${statusText}。所有新的原生 Gemini 格式请求都将受此影响。`);
    });

    // ==========================================================
    // [新增] 设置续写配置 (Set Resume Config) 接口
    // ==========================================================
    app.post("/api/set-resume-config", isAuthenticated, (req, res) => {
      const limit = parseInt(req.body.limit, 10);
      if (isNaN(limit) || limit < 0) {
          return res.status(400).send("无效的重试次数数值。");
      }
      this.resumeLimit = limit;
      this.enableResume = limit > 0;
      
      const statusText = this.enableResume ? `已启用 (重试限制: ${limit})` : "已关闭";
      this.logger.info(`[WebUI] 截断自动续写功能配置更新: ${statusText}`);
      res.status(200).send(`自动续写功能${statusText}。`);
    });

    app.use(this._createAuthMiddleware());

    app.get("/v1/models", (req, res) => {
      this.requestHandler.processModelListRequest(req, res);
    });

    app.post("/v1/chat/completions", (req, res) => {
      this.requestHandler.processOpenAIRequest(req, res);
    });
    app.all(/(.*)/, (req, res) => {
      this.requestHandler.processRequest(req, res);
    });

    return app;
  }

  async _startWebSocketServer() {
    this.wsServer = new WebSocket.Server({
      port: this.config.wsPort,
      host: this.config.host,
    });
    this.wsServer.on("connection", (ws, req) => {
      this.connectionRegistry.addConnection(ws, {
        address: req.socket.remoteAddress,
      });
    });
  }
}

// ===================================================================================
// MAIN INITIALIZATION
// ===================================================================================

async function initializeServer() {
  const initialAuthIndex = parseInt(process.env.INITIAL_AUTH_INDEX, 10) || 1;
  try {
    const serverSystem = new ProxyServerSystem();
    await serverSystem.start(initialAuthIndex);
  } catch (error) {
    console.error("❌ 服务器启动失败:", error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  initializeServer();
}

module.exports = { ProxyServerSystem, BrowserManager, initializeServer };