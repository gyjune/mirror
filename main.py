# -*- coding: utf-8 -*-
import re
import requests
from flask import Flask, Response, redirect, request
from requests.exceptions import (
    ChunkedEncodingError, ContentDecodingError, ConnectionError,
    StreamConsumedError, ReadTimeout, TooManyRedirects
)
from requests.utils import (
    stream_decode_response_unicode, iter_slices, CaseInsensitiveDict
)
from urllib3.exceptions import (
    DecodeError, ReadTimeoutError, ProtocolError, MaxRetryError
)
from urllib.parse import quote
import os

# -------------------------- 完整配置保留（已添加gyj07、gyj1980白名单）--------------------------
# jsDelivr镜像开关：1=启用（加速静态文件），0=关闭（纯代理）
jsdelivr = 0
# 文件大小限制：默认999GB（相当于无限制，保留原配置逻辑）
size_limit = 1024 * 1024 * 1024 * 999
# 白名单：已添加 gyj07、gyj1980（支持这三个用户的所有仓库，保留原规则格式）
# 规则说明：每行一个规则，支持 "用户名"（所有仓库）、"用户名/仓库名"（指定仓库）、"*/仓库名"（所有用户的该仓库）
white_list = '''
gyjune          # 允许代理你所有仓库（gyjune/开头）
gyj07           # 允许代理 gyj07 的所有仓库
gyj1980         # 允许代理 gyj1980 的所有仓库
gyjune/mirror   # 允许代理你这个mirror仓库（精确匹配，可保留）
'''
# 黑名单：禁止代理的仓库（规则格式同白名单，优先级低于白名单）
black_list = '''
# 示例：禁止代理某用户的仓库
# bad-user
# bad-user/bad-repo
'''
# pass_list：直接跳转jsDelivr的仓库（忽略jsdelivr开关，优先级最高）
pass_list = '''
# 示例：指定仓库强制用jsDelivr
# gyjune/fast-repo
'''

# 服务配置（保留原监听逻辑，确保安全）
HOST = '127.0.0.1'  # 监听本地（必须通过Nginx反代，不直接暴露）
PORT = 80            # 服务端口（可通过环境变量覆盖）
# 静态资源：适配仓库根目录favicon.ico（不依赖外部CDN）
FAVICON_PATH = os.path.join(os.path.dirname(__file__), 'favicon.ico')
# -------------------------- 核心优化：INDEX_HTML（贴近原版gh-proxy风格）--------------------------
INDEX_HTML = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Proxy by gyjune/mirror</title>
    <link rel="icon" href="/favicon.ico" type="image/vnd.microsoft.icon">
    <style>
        /* 原版风格：简洁黑白灰配色，紧凑布局 */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #fafbfc; 
            color: #24292e; 
            line-height: 1.5; 
            padding: 2rem 1rem;
        }
        .container { 
            max-width: 700px; 
            margin: 0 auto; 
        }
        /* 标题：贴近原版粗体+灰色副标题 */
        h1 { 
            font-size: 2rem; 
            font-weight: 600; 
            margin-bottom: 0.5rem; 
            color: #24292e;
        }
        .subtitle { 
            font-size: 1rem; 
            color: #6a737d; 
            margin-bottom: 2rem; 
            font-weight: 400;
        }
        /* 输入框组：原版横向紧凑布局 */
        .input-group { 
            display: flex; 
            width: 100%; 
            margin-bottom: 1.5rem; 
        }
        #url-input { 
            flex: 1; 
            padding: 0.75rem 1rem; 
            font-size: 1rem; 
            border: 1px solid #d1d5da; 
            border-right: none; 
            border-radius: 3px 0 0 3px; 
            outline: none;
        }
        #url-input:focus { 
            border-color: #0366d6; 
            box-shadow: 0 0 0 3px rgba(3, 102, 214, 0.1); 
        }
        #submit-btn { 
            padding: 0 1.25rem; 
            font-size: 1rem; 
            background: #0366d6; 
            color: white; 
            border: none; 
            border-radius: 0 3px 3px 0; 
            cursor: pointer; 
            font-weight: 500;
        }
        #submit-btn:hover { 
            background: #0256b3; 
        }
        /* 支持列表：原版灰色小字体+项目符号 */
        .support-list { 
            font-size: 0.875rem; 
            color: #6a737d; 
            margin-bottom: 2rem; 
        }
        .support-list h3 { 
            font-size: 0.9rem; 
            color: #24292e; 
            margin-bottom: 0.5rem; 
            font-weight: 600;
        }
        .support-list ul { 
            list-style-type: disc; 
            margin-left: 1.5rem; 
        }
        /* 底部说明：原版灰色细字体 */
        .footer { 
            font-size: 0.8rem; 
            color: #959da5; 
            border-top: 1px solid #eaecef; 
            padding-top: 1rem; 
            margin-top: 2rem;
        }
        .footer a { 
            color: #0366d6; 
            text-decoration: none; 
        }
        .footer a:hover { 
            text-decoration: underline; 
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 标题区域：贴近原版格式 -->
        <h1>GitHub Proxy</h1>
        <p class="subtitle">gyjune/mirror 代理服务 · 加速GitHub资源访问</p>
        
        <!-- 输入表单：原版横向布局，无多余样式 -->
        <div class="input-group">
            <form action="/" method="get" style="width: 100%; display: flex;">
                <input 
                    type="text" 
                    id="url-input" 
                    name="q" 
                    placeholder="输入GitHub链接（例：https://github.com/gyjune/mirror）" 
                    required
                    style="flex: 1;"
                >
                <button type="submit" id="submit-btn">Go</button>
            </form>
        </div>
        
        <!-- 支持场景：原版项目符号列表，简洁明了 -->
        <div class="support-list">
            <h3>支持资源类型：</h3>
            <ul>
                <li>GitHub Releases 安装包下载（.zip/.tar.gz）</li>
                <li>GitHub Blob 代码文件预览/下载</li>
                <li>Raw.githubusercontent.com 原始文件</li>
                <li>Gist 代码片段访问</li>
                <li>Git 仓库信息查询（info/git-* 接口）</li>
            </ul>
        </div>
        
        <div class="support-list">
            <h3>白名单限制：</h3>
            <ul>
                <li>仅允许代理 gyjune、gyj07、gyj1980 账号下的仓库</li>
                <li>单个文件大小限制：999GB（无感知限制）</li>
            </ul>
        </div>
        
        <!-- 底部说明：贴近原版版权+链接格式 -->
        <div class="footer">
            <p>基于 GitHub Proxy 项目修改 | <a href="https://github.com/gyjune/mirror" target="_blank">gyjune/mirror</a></p>
        </div>
    </div>
</body>
</html>
'''

# -------------------------- 原初始化逻辑完整保留（不简化）--------------------------
# 解析黑白名单（保留原规则处理逻辑：去空格、分割路径、支持通配符）
def parse_list(list_str):
    parsed = []
    for line in list_str.strip().split('\n'):
        # 跳过注释和空行
        line = line.strip().split('#')[0].strip()
        if not line:
            continue
        # 分割用户/仓库（支持通配符*）
        parts = tuple(part.strip() for part in line.split('/'))
        parsed.append(parts)
    return parsed

white_list = parse_list(white_list)
black_list = parse_list(black_list)
pass_list = parse_list(pass_list)

# 初始化Flask应用（保留原配置）
app = Flask(__name__)
CHUNK_SIZE = 1024 * 10  # 10KB分片传输（避免内存溢出，保留原大小）
# 重置requests默认头（避免携带Worker标识，保留原逻辑）
requests.sessions.default_headers = lambda: CaseInsensitiveDict()

# -------------------------- 原正则匹配规则完整保留（不简化，覆盖所有场景）--------------------------
# 1. Releases/Archive（含作者/仓库分组，用于黑白名单校验）
exp1 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:releases|archive)/.*$')
# 2. Blob/Raw（含作者/仓库分组）
exp2 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:blob|raw)/.*$')
# 3. Git操作接口（含作者/仓库分组）
exp3 = re.compile(r'^(?:https?://)?github\.com/(?P<author>.+?)/(?P<repo>.+?)/(?:info|git-).*$')
# 4. Raw内容（含作者/仓库分组）
exp4 = re.compile(r'^(?:https?://)?raw\.(?:githubusercontent|github)\.com/(?P<author>.+?)/(?P<repo>.+?)/.+?/.+$')
# 5. Gist内容（含作者分组，Gist无repo概念）
exp5 = re.compile(r'^(?:https?://)?gist\.(?:githubusercontent|github)\.com/(?P<author>.+?)/.+?/.+$')

# -------------------------- 原工具函数完整保留（不简化，确保功能正常）--------------------------
# 重写requests的iter_content（禁止自动解码，保留原二进制流，解决大文件传输问题）
def iter_content(self, chunk_size=1, decode_unicode=False):
    def generate():
        # 处理urllib3流模式（保留原异常捕获）
        if hasattr(self.raw, 'stream'):
            try:
                for chunk in self.raw.stream(chunk_size, decode_content=False):
                    yield chunk
            except ProtocolError as e:
                raise ChunkedEncodingError(e)
            except DecodeError as e:
                raise ContentDecodingError(e)
            except ReadTimeoutError as e:
                raise ConnectionError(e)
        else:
            # 处理标准文件流（避免空chunk）
            while True:
                chunk = self.raw.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        self._content_consumed = True

    # 处理流已消费异常（保留原逻辑）
    if self._content_consumed and isinstance(self._content, bool):
        raise StreamConsumedError()
    elif chunk_size is not None and not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be an int, it is instead a %s." % type(chunk_size))

    # 处理已缓存内容（复用已读取数据，优化性能）
    reused_chunks = iter_slices(self._content, chunk_size)
    stream_chunks = generate()
    chunks = reused_chunks if self._content_consumed else stream_chunks

    # 处理unicode解码（保留原逻辑，支持文本响应）
    if decode_unicode:
        chunks = stream_decode_response_unicode(chunks, self)

    return chunks

# 检查URL是否符合GitHub规则（返回匹配对象，用于后续黑白名单校验）
def check_url(u):
    for exp in (exp1, exp2, exp3, exp4, exp5):
        m = exp.match(u)
        if m:
            return m
    return False

# 校验黑白名单（保留原优先级：白名单→黑名单→pass_list，逻辑不简化）
def check_access(match_obj):
    if not match_obj:
        return False, "Invalid URL: 链接格式不支持"
    
    # 提取匹配分组（作者/仓库，适配不同链接类型）
    groups = match_obj.groupdict()
    author = groups.get('author')
    repo = groups.get('repo', '')  # Gist无repo，默认为空
    # 构建校验键（支持 "作者"、"作者/仓库"、"*/仓库" 规则）
    check_key = (author, repo) if repo else (author,)

    # 1. 白名单校验（无白名单则跳过，有则必须匹配）
    if white_list:
        allowed = False
        for rule in white_list:
            # 规则长度1：匹配作者（例：规则(gyjune,) → 匹配所有gyjune的仓库）
            if len(rule) == 1:
                if check_key[0] == rule[0] or rule[0] == '*':
                    allowed = True
                    break
            # 规则长度2：匹配作者/仓库（例：规则(gyjune, mirror) → 精确匹配）
            elif len(rule) == 2:
                if (check_key[0] == rule[0] or rule[0] == '*') and (check_key[1] == rule[1] or rule[1] == '*'):
                    allowed = True
                    break
        if not allowed:
            return False, f"Forbidden by White List: 仅允许代理 {', '.join(['/'.join(r) for r in white_list])} 相关仓库"
    
    # 2. 黑名单校验（匹配则禁止）
    for rule in black_list:
        if len(rule) == 1:
            if check_key[0] == rule[0] or rule[0] == '*':
                return False, f"Forbidden by Black List: 禁止代理 {rule[0]} 相关仓库"
        elif len(rule) == 2:
            if (check_key[0] == rule[0] or rule[0] == '*') and (check_key[1] == rule[1] or rule[1] == '*'):
                return False, f"Forbidden by Black List: 禁止代理 {('/'.join(rule))} 仓库"
    
    # 3. pass_list校验（匹配则直接跳转jsDelivr）
    for rule in pass_list:
        if len(rule) == 1:
            if check_key[0] == rule[0] or rule[0] == '*':
                return True, "pass"
        elif len(rule) == 2:
            if (check_key[0] == rule[0] or rule[0] == '*') and (check_key[1] == rule[1] or rule[1] == '*'):
                return True, "pass"
    
    return True, "allow"

# -------------------------- 原视图函数完整保留（不简化，功能全保留）--------------------------
# 主页（支持参数跳转、返回完整HTML，不简化）
@app.route('/')
def index():
    # 处理参数跳转（?q=链接 → 重定向到 /链接）
    if 'q' in request.args:
        target = request.args.get('q').strip()
        # 修复链接格式（避免//被合并）
        if target and not target.startswith('http'):
            target = f'https://{target}'
        return redirect(f'/{quote(target, safe=":/")}')
    # 返回完整主页HTML
    return INDEX_HTML

# 图标（读取仓库本地文件，不依赖外部，保留异常处理）
@app.route('/favicon.ico')
def favicon():
    try:
        # 读取本地favicon.ico（二进制模式）
        with open(FAVICON_PATH, 'rb') as f:
            return Response(f.read(), content_type='image/vnd.microsoft.icon')
    except Exception as e:
        # 降级：返回空响应（避免500错误）
        return Response(b'', content_type='image/vnd.microsoft.icon', status=404)

# 核心代理接口（保留所有分支逻辑、异常处理，不简化）
@app.route('/<path:u>', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
def proxy_handler(u):
    # 修复URL格式（uwsgi会将//转为/，保留原处理逻辑）
    u = u.strip()
    if not u.startswith('http'):
        u = f'https://{u}'
    # 修复 https:/ 格式（少一个/的异常场景）
    if u.rfind('://', 3, 9) == -1:
        u = u.replace('s:/', 's://', 1)

    # 1. 链接校验（黑白名单、格式检查）
    match_obj = check_url(u)
    access_allowed, access_msg = check_access(match_obj)
    if not access_allowed:
        return Response(access_msg, status=403, headers={'content-type': 'text/plain; charset=utf-8'})
    pass_by = (access_msg == "pass")

    # 2. pass_list/ jsDelivr 跳转（保留原分支逻辑）
    if (jsdelivr or pass_by) and exp2.match(u):
        # Blob链接 → 跳转jsDelivr
        new_u = u.replace('/blob/', '@', 1).replace('github.com', 'cdn.jsdelivr.net/gh', 1)
        return redirect(new_u, code=302)  # 302临时跳转，适配链接变化
    elif (jsdelivr or pass_by) and exp4.match(u):
        # Raw链接 → 跳转jsDelivr（保留原正则替换逻辑）
        new_u = re.sub(r'(\.com/.*?/.+?)/(.+?/)', r'\1@\2', u, 1)
        # 适配 raw.github.com 和 raw.githubusercontent.com
        if 'raw.githubusercontent.com' in new_u:
            new_u = new_u.replace('raw.githubusercontent.com', 'cdn.jsdelivr.net/gh')
        else:
            new_u = new_u.replace('raw.github.com', 'cdn.jsdelivr.net/gh')
        return redirect(new_u, code=302)
    elif pass_by:
        # pass_list但非Blob/Raw → 直接跳转原链接
        full_url = u + request.url.replace(request.base_url, '', 1)
        # 修复链接格式（避免https:/问题）
        if full_url.startswith('https:/') and not full_url.startswith('https://'):
            full_url = f'https://{full_url[7:]}'
        return redirect(full_url, code=302)

    # 3. Blob链接转为Raw（非jsDelivr模式，保留原逻辑）
    if exp2.match(u):
        u = u.replace('/blob/', '/raw/', 1)

    # 4. 构建完整代理URL（拼接查询参数、路径，保留原逻辑）
    full_proxy_url = u + request.url.replace(request.base_url, '', 1)
    if full_proxy_url.startswith('https:/') and not full_proxy_url.startswith('https://'):
        full_proxy_url = f'https://{full_proxy_url[7:]}'

    # 5. 发起代理请求（保留所有参数、异常处理，不简化）
    headers = {}
    req_headers = dict(request.headers)
    # 移除Host头（避免目标服务器校验不通过）
    if 'Host' in req_headers:
        req_headers.pop('Host')

    try:
        # 发起流式请求（避免大文件占用内存，保留原参数）
        proxy_res = requests.request(
            method=request.method,
            url=full_proxy_url,
            data=request.data,
            headers=req_headers,
            stream=True,
            allow_redirects=False,  # 手动处理重定向，保留原逻辑
            timeout=30  # 超时时间30秒，避免僵死请求
        )

        # 处理大文件（超过限制则跳转原链接，保留原逻辑）
        if 'Content-length' in proxy_res.headers:
            try:
                content_length = int(proxy_res.headers['Content-length'])
                if content_length > size_limit:
                    return redirect(full_proxy_url, code=302)
            except (ValueError, TypeError):
                pass  # 长度解析失败则忽略限制

        # 构建响应头（传递原响应头，删除限制头）
        res_headers = dict(proxy_res.headers)
        # 暴露所有头给前端（解决跨域获取头信息问题）
        res_headers['access-control-expose-headers'] = '*'
        res_headers['access-control-allow-origin'] = '*'
        # 删除安全限制头（避免前端执行报错）
        for restricted_header in ['content-security-policy', 'content-security-policy-report-only', 'clear-site-data']:
            if restricted_header in res_headers:
                res_headers.pop(restricted_header)

        # 处理重定向（保留原逻辑：GitHub内重定向→代理路径，外部→二次代理）
        if proxy_res.status_code in [301, 302, 307, 308] and 'Location' in proxy_res.headers:
            redirect_location = proxy_res.headers['Location']
            if check_url(redirect_location):
                # GitHub内部重定向 → 改为代理路径
                res_headers['Location'] = f'/{quote(redirect_location, safe=":/")}'
            else:
                # 外部重定向 → 二次代理（递归调用，保留原逻辑）
                return proxy_handler(redirect_location.lstrip('https://'))

        # 流式返回响应（避免内存溢出，保留原分片逻辑）
        def generate_response_chunks():
            try:
                for chunk in iter_content(proxy_res, chunk_size=CHUNK_SIZE):
                    if chunk:
                        yield chunk
            finally:
                # 确保请求关闭（避免资源泄漏）
                proxy_res.close()

        # 返回流式响应（保留原状态码、头信息）
        return Response(
            generate_response_chunks(),
            status=proxy_res.status_code,
            headers=res_headers
        )

    # 异常处理（覆盖所有可能异常，返回明确提示，不简化）
    except ConnectionError as e:
        return Response(f'Server Connection Error: 无法连接到目标服务器（{str(e)}）', status=502, headers={'content-type': 'text/plain; charset=utf-8'})
    except ReadTimeout as e:
        return Response(f'Request Timeout: 请求超时（{str(e)}）', status=504, headers={'content-type': 'text/plain; charset=utf-8'})
    except TooManyRedirects as e:
        return Response(f'Too Many Redirects: 重定向次数过多（{str(e)}）', status=400, headers={'content-type': 'text/plain; charset=utf-8'})
    except MaxRetryError as e:
        return Response(f'Max Retries Exceeded: 最大重试次数超限（{str(e)}）', status=502, headers={'content-type': 'text/plain; charset=utf-8'})
    except Exception as e:
        # 捕获其他未知异常（避免服务崩溃）
        return Response(f'Proxy Internal Error: {str(e)}', status=500, headers={'content-type': 'text/plain; charset=utf-8'})

# 启动配置（保留原安全逻辑：生产环境关闭debug）
if __name__ == '__main__':
    app.debug = False  # 禁止生产环境启用debug（避免代码泄露、安全风险）
    app.run(host=HOST, port=PORT, threaded=True)  # 启用多线程，提升并发能力
