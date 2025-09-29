#! /usr/bin/env bash
set -e  # 脚本执行出错时立即退出（避免错误传播）

# 加载uwsgi-nginx基础环境（适配tiangolo/uwsgi-nginx-flask镜像）
/uwsgi-nginx-entrypoint.sh

# 获取Nginx监听端口（支持环境变量覆盖，默认80端口）
USE_LISTEN_PORT=${LISTEN_PORT:-80}

# 检查是否存在自定义Nginx配置（优先使用用户自定义配置）
if [ -f /app/nginx.conf ]; then
    # 复制用户自定义配置到Nginx默认目录（覆盖默认配置）
    cp /app/nginx.conf /etc/nginx/nginx.conf
else
    # 生成默认Nginx配置（适配mirror代理服务，保留完整参数）
    content_server='server {\n'
    # 配置监听端口（支持动态端口）
    content_server=$content_server"    listen ${USE_LISTEN_PORT};\n"
    # 静态资源请求处理（优先查找本地静态文件）
    content_server=$content_server'    location / {\n'
    content_server=$content_server'        try_files $uri @app;\n'  # 先查本地文件，不存在则转发到Python服务
    content_server=$content_server'        expires 1d;  # 静态资源缓存1天（优化性能）\n'
    content_server=$content_server'    }\n'
    # Python服务转发配置（适配uwsgi通信）
    content_server=$content_server'    location @app {\n'
    content_server=$content_server'        include uwsgi_params;  # 加载uwsgi标准参数\n'
    content_server=$content_server'        uwsgi_pass unix:///tmp/uwsgi.sock;  # 与uwsgi通信的Socket路径\n'
    # 调整uwsgi缓冲区（解决大请求/响应问题，避免502错误）
    content_server=$content_server'        uwsgi_buffer_size 256k;\n'
    content_server=$content_server'        uwsgi_buffers 32 512k;\n'
    content_server=$content_server'        uwsgi_busy_buffers_size 512k;\n'
    # 超时配置（适配大文件传输，避免连接被提前关闭）
    content_server=$content_server'        proxy_connect_timeout 300s;\n'
    content_server=$content_server'        proxy_read_timeout 300s;\n'
    content_server=$content_server'        proxy_send_timeout 300s;\n'
    content_server=$content_server'    }\n'
    # 错误页面配置（返回友好错误提示）
    content_server=$content_server'    error_page 403 404 500 502 503 504 /error.html;\n'
    content_server=$content_server'    location = /error.html {\n'
    content_server=$content_server'        root /app;\n'  # 错误页面放在仓库根目录（可自行添加error.html）
    content_server=$content_server'        internal;\n'  # 仅内部访问（禁止直接请求）
    content_server=$content_server'    }\n'
    content_server=$content_server'}\n'

    # 生成Nginx站点配置文件（保存到Nginx默认站点目录）
    printf "$content_server" > /etc/nginx/conf.d/mirror.conf
fi

# 执行传入的命令（启动uwsgi服务，适配Docker CMD参数）
exec "$@"
