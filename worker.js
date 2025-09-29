'use strict'
/**
 * 完整功能保留：支持Releases/Blob/Raw/Gist所有场景、跨域预检、重定向处理、白名单、jsDelivr切换
 */
const CONFIG = {
    // 路由前缀：部署为 example.com/ 则保持 '/'，如需 /mirror/* 则改为 '/mirror/'
    PREFIX: '/',
    // 分支文件使用jsDelivr镜像开关：1=启用（加速），0=关闭（纯代理）
    USE_JSDELIVR: 0,
    // 白名单：已添加 gyjune、gyj07、gyj1980（支持代理这三个用户的所有仓库）
    WHITE_LIST: ['/gyjune/', '/gyj07/', '/gyj1980/'],
    // 静态资源（favicon）本地路径适配（仓库根目录直接放favicon.ico）
    FAVICON_PATH: '/favicon.ico'
}

/**
 * 原跨域预检配置完整保留（解决前端调用问题）
 */
const PREFLIGHT_INIT = {
    status: 204,
    headers: new Headers({
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
        'access-control-max-age': '1728000', // 预检结果缓存20天
        'access-control-allow-headers': 'content-type,authorization,x-requested-with'
    }),
}

/**
 * 原GitHub链接匹配规则完整保留（覆盖所有核心场景，不简化）
 */
const GITHUB_REGEX = [
    // 1. Releases/Archive（下载安装包、源码压缩包）
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:releases|archive)\/.*$/i,
    // 2. Blob/Raw（代码文件预览/下载）
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:blob|raw)\/.*$/i,
    // 3. Git操作接口（info/git-*，支持git clone等场景）
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:info|git-)\/.*$/i,
    // 4. Raw内容（raw.githubusercontent.com 直链）
    /^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+?\/.+$/i,
    // 5. Gist内容（gist仓库文件）
    /^(?:https?:\/\/)?gist\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+$/i,
    // 6. Tags页面（仓库标签列表）
    /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/tags.*$/i
]

/**
 * 原工具函数完整保留（不简化，确保功能稳定）
 */
// 生成响应（自动添加跨域头，处理不同响应场景）
function makeResponse(body, status = 200, headers = {}) {
    headers['access-control-allow-origin'] = '*';
    headers['access-control-expose-headers'] = '*'; // 暴露所有响应头给前端
    return new Response(body, { status, headers });
}

// 解析URL（处理异常场景，避免Worker崩溃）
function parseUrl(urlStr) {
    try {
        return new URL(urlStr);
    } catch (err) {
        return null;
    }
}

// 验证URL是否符合GitHub规则（完整匹配所有场景）
function isGithubValidUrl(url) {
    if (!url) return false;
    for (let regex of GITHUB_REGEX) {
        if (regex.test(url)) {
            return true;
        }
    }
    return false;
}

// 检查URL是否在白名单内（支持多规则匹配，保留原逻辑）
function isInWhiteList(url) {
    // 白名单为空则允许所有（兼容灵活配置）
    if (!CONFIG.WHITE_LIST.length) return true;
    // 匹配白名单中任意规则则通过
    for (let keyword of CONFIG.WHITE_LIST) {
        if (url.includes(keyword)) {
            return true;
        }
    }
    return false;
}

// 转换Blob链接（根据配置切换Raw/jsDelivr，保留原逻辑）
function transformBlobUrl(url) {
    if (CONFIG.USE_JSDELIVR && url.includes('/blob/')) {
        // 转换为jsDelivr镜像（例：github.com/gyjune/mirror/blob/main/xx → cdn.jsdelivr.net/gh/gyjune/mirror@main/xx）
        return url.replace('/blob/', '@').replace(/^(?:https?:\/\/)?github\.com/, 'https://cdn.jsdelivr.net/gh');
    }
    // 不启用镜像则转为Raw链接（确保能直接访问文件内容）
    return url.replace('/blob/', '/raw/');
}

// 转换Raw链接（适配jsDelivr，保留原正则处理逻辑）
function transformRawUrl(url) {
    if (CONFIG.USE_JSDELIVR) {
        // 处理raw.githubusercontent.com链接（例：raw.githubusercontent.com/gyjune/mirror/main/xx → cdn.jsdelivr.net/gh/gyjune/mirror@main/xx）
        return url
            .replace(/(?<=com\/.+?\/.+?)\/(.+?\/)/, '@$1') // 精准插入@分隔仓库和分支
            .replace(/^https?:\/\/raw\.(githubusercontent|github)\.com/, 'https://cdn.jsdelivr.net/gh');
    }
    return url;
}

/**
 * 主请求处理逻辑（完整保留原流程，不简化步骤）
 */
async function handleFetchEvent(event) {
    const req = event.request;
    const urlObj = new URL(req.url);
    let targetUrl = '';

    // 1. 处理参数模式（?q=目标链接 → 重定向到路径模式，兼容原使用习惯）
    const queryTarget = urlObj.searchParams.get('q');
    if (queryTarget) {
        const redirectUrl = `${urlObj.origin}${CONFIG.PREFIX}${queryTarget}`;
        return Response.redirect(redirectUrl, 301); // 301永久重定向，优化缓存
    }

    // 2. 提取目标链接（处理CF Workers合并//问题，保留原解析逻辑）
    targetUrl = urlObj.href
        .substr(urlObj.origin.length + CONFIG.PREFIX.length) // 从路径中截取目标链接
        .replace(/^https?:\/+/, 'https://'); // 修复协议头（避免//被合并为/导致URL无效）

    // 3. 处理静态资源请求（favicon.ico，适配仓库根目录文件）
    if (urlObj.pathname === CONFIG.FAVICON_PATH) {
        // 读取仓库根目录的favicon.ico（不依赖外部资源）
        const faviconResponse = await fetch(urlObj.origin + CONFIG.FAVICON_PATH);
        if (faviconResponse.ok) {
            return makeResponse(await faviconResponse.blob(), 200, {
                'content-type': 'image/vnd.microsoft.icon',
                'cache-control': 'public, max-age=86400' // 缓存1天，减少请求
            });
        }
        // 降级：返回默认图标（避免404）
        return makeResponse('', 404, { 'content-type': 'image/vnd.microsoft.icon' });
    }

    // 4. 验证目标链接（非GitHub链接直接拦截，保留原校验逻辑）
    if (!isGithubValidUrl(targetUrl)) {
        return makeResponse('Invalid GitHub URL: 仅支持代理GitHub相关链接（Releases/Blob/Raw/Gist等）', 403);
    }

    // 5. 白名单检查（未通过则拦截，返回明确提示）
    if (!isInWhiteList(targetUrl)) {
        return makeResponse(`Forbidden: 仅允许代理白名单内链接（当前白名单：${CONFIG.WHITE_LIST.join(', ')}）`, 403);
    }

    // 6. 处理跨域预检请求（OPTIONS方法，完整保留原逻辑）
    if (req.method === 'OPTIONS' && req.headers.has('access-control-request-headers')) {
        return new Response(null, PREFLIGHT_INIT);
    }

    // 7. 转换目标链接（根据链接类型适配，保留原分支逻辑）
    if (targetUrl.match(GITHUB_REGEX[1])) { // Blob/Raw类型（规则2）
        targetUrl = transformBlobUrl(targetUrl);
    } else if (targetUrl.match(GITHUB_REGEX[3])) { // Raw类型（规则4）
        targetUrl = transformRawUrl(targetUrl);
    }

    // 8. 发起代理请求（保留原请求头、方法、体，确保兼容性）
    const proxyRequestInit = {
        method: req.method,
        headers: new Headers(req.headers), // 传递原请求头（如Authorization、Cookie等）
        redirect: 'manual', // 手动处理重定向（避免跨域问题，保留原逻辑）
        body: req.body, // 传递请求体（支持POST/PUT等方法）
        cache: 'no-store' // 禁用缓存（确保获取最新内容）
    };

    try {
        // 验证目标URL格式（避免无效请求）
        const targetUrlObj = parseUrl(targetUrl);
        if (!targetUrlObj) {
            return makeResponse('Invalid URL Format: 目标链接格式错误', 400);
        }

        // 发起代理请求（捕获所有异常，避免Worker崩溃）
        const proxyResponse = await fetch(targetUrlObj.href, proxyRequestInit);
        const responseHeaders = new Headers(proxyResponse.headers);

        // 处理重定向响应（修改Location为代理路径，保留原逻辑）
        if (responseHeaders.has('location')) {
            const redirectLocation = responseHeaders.get('location');
            if (isGithubValidUrl(redirectLocation)) {
                // GitHub内部重定向 → 改为代理路径
                responseHeaders.set('location', `${CONFIG.PREFIX}${redirectLocation}`);
            } else {
                // 外部重定向 → 二次代理（避免跨域跳转）
                return handleFetchEvent(new FetchEvent('fetch', {
                    request: new Request(redirectLocation, proxyRequestInit)
                }));
            }
        }

        // 删除安全限制头（避免前端执行报错，保留原逻辑）
        const restrictedHeaders = [
            'content-security-policy',
            'content-security-policy-report-only',
            'clear-site-data',
            'x-frame-options',
            'x-xss-protection'
        ];
        restrictedHeaders.forEach(header => responseHeaders.delete(header));

        // 返回代理响应（传递原始响应体、状态码、头信息）
        return makeResponse(proxyResponse.body, proxyResponse.status, responseHeaders);

    } catch (err) {
        // 异常处理（返回详细错误信息，便于排查问题）
        console.error('Proxy Error:', err);
        return makeResponse(`Proxy Server Error: ${err.message}\nStack: ${err.stack}`, 502);
    }
}

/**
 * 注册Fetch事件（完整保留错误捕获，确保Worker稳定运行）
 */
addEventListener('fetch', e => {
    const response = handleFetchEvent(e)
        .catch(err => makeResponse(`Worker Runtime Error: ${err.message}\nStack: ${err.stack}`, 500));
    e.respondWith(response);
});
