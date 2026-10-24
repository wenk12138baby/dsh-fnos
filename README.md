# dsh-fnos

把 **DeepSeek Harness (dsh)** 打包成 **飞牛 fnOS (fnOS)** 应用，并修复官方包在飞牛上白屏的问题。

**当前版本：`0.2.1-rc.2`**（跟随 dsh 版本）

作者：**温克Baby**

---

## 这个仓库解决什么问题

官方提供的 dsh fpk 在飞牛上装好后**打开是白屏**。原因是网关代理层有三处不适配：

| 问题 | 现象 | 原因 |
|---|---|---|
| ① Cookie 的 Host 绑定 | 静态资源 401 | 启动令牌换到的 cookie 绑在 `Host: 127.0.0.1`，浏览器带的是 NAS 的 Host（如 `192.168.88.12:3080`），签名校验直接拒绝 |
| ② gzip 未解压就改写 | `<base href>` 没被替换 | 上游响应是 gzip，代理直接在压缩字节上做字符串替换，等于没改 |
| ③ 相对资源前缀替换错误 | 所有 JS/CSS 404 | `"./${p}"` 被替换成 `".${p}"`，丢掉了斜杠 |

修好这三处后，飞牛桌面里点开应用即可正常使用。

详细排查过程见 [`patches/排查报告.md`](patches/排查报告.md)。

---

## 目录结构

```
gateway/server.mjs          网关：反向代理 + 令牌转发 + 响应改写
scripts/detect-node.sh      启动时探测可用的 Node（飞牛自带 nodejs_v24）
config/privilege            应用权限声明
config/resource             资源配置
ui/config                   飞牛桌面入口配置
ui/images/                  应用图标
patches/proxy.js            修复后的代理实现（与 server.mjs 同源，单独留档便于对比）
patches/排查报告.md         三个问题的定位过程与验证方法
docs/使用说明.txt            面向使用者的简明说明
docs/DeepSeek-Harness-使用教程.md      11 章图文教程
docs/使用教程（温克Baby）.pdf          同一教程的 PDF 版
docs/images/                教程配图
```

> **可安装的 fpk 在 [Releases](https://github.com/wenk12138baby/dsh-fnos/releases) 里**，
> 不放在仓库中（84 MB，超出常规仓库文件的合理体积）。

---

## 安装

### 方式一：直接装 fpk（推荐）

1. 到 [Releases](https://github.com/wenk12138baby/dsh-fnos/releases/tag/v0.2.1-rc.2) 下载 `DeepSeekHarness-0.2.1-rc.2-fnos-x86.fpk`
2. 飞牛 → 应用中心 → 手动安装 → 选择该文件
3. 装完在桌面点开应用

**直链：**

```
https://github.com/wenk12138baby/dsh-fnos/releases/download/v0.2.1-rc.2/DeepSeekHarness-0.2.1-rc.2-fnos-x86.fpk
```

**校验：**

| 项 | 值 |
|---|---|
| 大小 | 88,231,135 字节（84.1 MB） |
| SHA256 | `9669E8A8BE77B287DC47A68B106098F73F6A15CAC65D9423AC94AA7D1DF7097B` |

```bash
# 下载后校验
sha256sum DeepSeekHarness-0.2.1-rc.2-fnos-x86.fpk
```

### 方式二：从本仓库的文件自行打包

```bash
# 目录结构要求：
#   app/
#     manifest
#     cmd/main
#     config/{privilege,resource}
#     ui/{config,images/}
#     app.tgz        ← 把 gateway/ scripts/ dsh/ 打进去

tar -czf app.tgz gateway scripts dsh
tar -czf package.tar manifest cmd config ui app.tgz
gzip package.tar
```

---

## 首次使用

装好后打开应用，需要：

1. **获取访问令牌**  
   在 NAS 上执行：
   ```bash
   grep -o 'token=[A-Za-z0-9_-]*' /vol*/@appdata/DeepSeekHarness/gateway.log | tail -1
   ```

2. **用带令牌的地址访问**  
   `http://<NAS地址>:3080/?token=<上一步拿到的令牌>`

3. **在设置里配置模型提供商**（DeepSeek API Key、或安装其他模型插件）

详细步骤见 [docs/使用说明.txt](docs/使用说明.txt)。

---

## 已知问题

| 现象 | 处理 |
|---|---|
| 页面提示「authentication required」 | 访问地址缺 `?token=`，按上面第 2 步补上 |
| 端口 3080 / 13080 被占用 | 卸载后残留进程未退出：`sudo fuser -k -n tcp 3080` / `13080` |
| 应用图标显示异常 | 确认 `ui/images/icon_256.png` 与 `icon_64.png` 都在 |

---

## 系统影响

- 安装位置：`/vol*/@appcenter/DeepSeekHarness`
- 数据目录：`/vol*/@apphome/DeepSeekHarness`（用户配置、会话）
- 运行目录：`/vol*/@appdata/DeepSeekHarness`（日志、pid）
- **不会修改系统文件**；卸载会保留用户数据目录

---

## 版本对应

| dsh 版本 | 本仓库版本 | 说明 |
|---|---|---|
| 0.2.1-rc.2 | 0.2.1-rc.2 | 当前版本，已修复白屏 |

---

## 许可证

MIT（见 [LICENSE](LICENSE)）

本项目对 DeepSeek Harness 的打包与修复部分由温克Baby 完成；
DeepSeek Harness 本身版权归其原作者所有。
