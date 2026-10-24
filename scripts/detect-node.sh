#!/bin/bash
# ============================================================================
#  detect-node.sh —— 选择一个可用的 Node.js 运行时
# ============================================================================
#  DSH 0.2.1-rc.2 依赖 `import.meta.main`，该特性从 Node 24.2.0 起提供。
#  低于此版本时 dsh 的 CLI 入口与沙箱 runner 会静默不执行，表现为「启动了
#  但什么也没发生」。所以这里必须做真实的特性探测，不能只看主版本号。
#
#  探测顺序：
#    1. 应用内置运行时（若本包带了 runtime/node）
#    2. fnOS 应用中心安装的 nodejs 应用（路径因版本/安装位置而异，用 glob + find）
#    3. 系统 PATH 与常见位置
#
#  输出：可用 Node 的绝对路径；找不到时输出空并返回 1。
#
#  注意：本脚本可能被手动执行，那时 TRIM_APPDEST 不存在。
#  set -u 下直接引用会崩，所以先用默认值兜底。
# ============================================================================

set -u

APP_DEST="${TRIM_APPDEST:-}"
if [ -z "${APP_DEST}" ]; then
    SELF_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
    if [ -n "${SELF_DIR}" ] && [ -d "${SELF_DIR}/.." ]; then
        APP_DEST=$(cd "${SELF_DIR}/.." && pwd)
    else
        APP_DEST=/var/apps/DeepSeekHarness
    fi
fi

FEATURE_PROBE='process.stdout.write(typeof import.meta.main === "boolean" ? "yes" : "no")'

# 判断一个 node 可执行文件是否满足要求。
# 先看版本号（快速排除 22/20 这类明显不够的），再做 import.meta.main 特性探测。
is_usable() {
    local bin="$1"
    [ -n "${bin}" ] || return 1
    [ -x "${bin}" ] || return 1

    # 版本号快速筛选：只接受 v24.2.0 及以上。
    # 这里不追求完整 semver，只要主版本 >=24 且 (主版本 >24 或 次版本 >=2)。
    local version
    version=$("${bin}" --version 2>/dev/null) || return 1
    case "${version}" in
        v24.*) ;;
        v25.*|v26.*|v27.*|v28.*|v29.*|v3[0-9].*) ;;
        *) return 1 ;;
    esac
    if [ "${version#v24.}" != "${version}" ]; then
        local minor=${version#v24.}
        minor=${minor%%.*}
        case "${minor}" in
            ''|*[!0-9]*) return 1 ;;
        esac
        [ "${minor}" -ge 2 ] || return 1
    fi

    # 特性探测：用 --input-type=module 从 stdin 执行，不落盘。
    local result
    result=$(printf '%s' "${FEATURE_PROBE}" | "${bin}" --input-type=module - 2>/dev/null)
    [ "${result}" = "yes" ]
}

# ── 候选列表 ────────────────────────────────────────────────────────────────
# fnOS 的 nodejs 应用可能装在任意存储空间（/vol1 /vol2 ...），
# 也可能用不同的 appname（nodejs_v24 / nodejs / nodejs24）。
# 硬编码单一路径不可靠，这里用 glob 展开 + find 兜底。

candidates=""

# 1) 应用内置运行时
candidates="${candidates} ${APP_DEST}/runtime/node/bin/node"

# 2) fnOS nodejs 应用：/var/apps/nodejs*/target/bin/node
for f in /var/apps/nodejs*/target/bin/node /var/apps/nodejs*/bin/node; do
    [ -e "$f" ] && candidates="${candidates} ${f}"
done

# 3) 直接扫描各存储空间的 @appcenter（fnOS 应用实际落盘位置）
for f in /vol*/@appcenter/nodejs*/target/bin/node; do
    [ -e "$f" ] && candidates="${candidates} ${f}"
done

# 4) PATH 与常见系统位置
path_node=$(command -v node 2>/dev/null || true)
[ -n "${path_node}" ] && candidates="${candidates} ${path_node}"
candidates="${candidates} /usr/local/bin/node /usr/bin/node /opt/node/bin/node"

# 5) 最后兜底：find 一次（限定深度，避免在 NAS 上扫全盘）
found=$(find /var/apps /vol1/@appcenter /vol2/@appcenter /usr/local /opt \
    -maxdepth 4 -type f -name node -perm -u+x 2>/dev/null | head -20)
for f in ${found}; do
    candidates="${candidates} ${f}"
done

# ── 逐个验证 ────────────────────────────────────────────────────────────────
for candidate in ${candidates}; do
    [ -n "${candidate}" ] || continue
    if is_usable "${candidate}"; then
        echo "${candidate}"
        exit 0
    fi
done

exit 1
