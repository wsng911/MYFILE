
# Docker容器

------

## 1、[青龙面板](https://github.com/whyour/qinglong)[IP:5700]

```
docker run -dit \
  -v $PWD/ql:/ql/data \
  -p 5700:5700 \
  --name qinglong \
  --hostname qinglong \
  --restart unless-stopped \
  whyour/qinglong:debian
```

更新面板

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock containrrr/watchtower -cR qinglong
```

```
#依赖安装
---------------------#NodeJs
crypto-js node-rsa
---------------------#Python3
pycryptodome
requests
beautifulsoup4
toml
rsa
```

### 通知机器人

```
TG_USER_ID
1413533617
.
@starnight_bot
6162104661:AAGbzJcjCZUW7lCYy8BC9hUQMBxx6aizFuM
@push_PT_bot
5284303512:AAHiRBP-L6GYfVq6gMIVoHVHb1GyTDONp8Y
@iiixiaoyu_bot
6087059820:AAGP9ixKgKTdqYcCUMipxQa9sqEVwcLDslc
#@Avaver_AI_bot
5802273018:AAF3J8JwEeQ2zFrm9TV0Db8ssDAMYm4m6vw
.
第一个值是企业id，第二个值是secret，第三个值@all(或者成员id)，第四个值是AgentID，第五个值是图片id  中间以逗号隔开
ww20f16ae8aa3d7054,XhAQhZUNek3ICsUTaPgPxSatXvXRdqgfXzKhfKplMiw,@all,1000004,2quAiuAUAwUizRasHvMyH6ICgFivjVNm2C2z4kMjApZ4iSjV9YEaIHkV2hMuKtyS5
```

### 常用签到脚本

#### A、[签到-阿里云盘、喜马拉雅、ikuu](https://github.com/wd210010/only_for_happly)

```
ql repo https://github.com/wd210010/only_for_happly.git "" "backup" "" ""
```

#### B、[PT签到、阿里云签到](https://github.com/Ecalose/MyCheckBox)

```
ql repo "https://github.com/Ecalose/MyCheckBox.git" "sh" "" "" "main" ""
```

#### C、[电信签到、兑换](https://github.com/leafTheFish/DeathNote/)

```
https://github.com/leafTheFish/DeathNote/blob/main/chinaTelecom.js
https://github.com/leafTheFish/DeathNote/blob/main/chinaTelecom_exchange.js
```

------

## 2、NGINX反代

```
#1CloudFlare新建证书，15年，打开小云朵
#SSL/TLS-->概述-->完全（严格）
#       -->源服务器-->创建证书-->ECC-->主机名-->有效期-->创建
#将新建证书的值复制到公钥、密钥
#创建nginx目录结构
mkdir -p /home/nginx/certs &&cd /home/nginx/certs
#公钥
touch cert.pem
#密钥
touch key.pem
#创建nginx.conf文件
touch /home/nginx/nginx.conf
```

```
#2部署
docker run -d \
  --name nginx \
  --restart=always \
  -p 80:80 \
  -p 443:443 \
  -v /home/nginx/nginx.conf:/etc/nginx/nginx.conf \
  -v /home/nginx/certs:/etc/nginx/certs \
  -v /home/nginx/html:/usr/share/nginx/html \
  nginx:latest
```

<details>
<summary>nginx.conf</summary>
```events {
  worker_connections 1024;
}
http {
  # qinglong
  server {
    listen 443 ssl http2;
    server_name ql.idays.gq;
    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    location / {
      proxy_pass http://ip.idays.gq:5700;
    }
  }
  # chat
  server {
    listen 443 ssl http2;
    server_name chat.idays.gq;
    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    location / {
      proxy_pass http://ip.idays.gq:3002;
    }
  }
  # vertex
  server {
    listen 443 ssl http2;
    server_name v.idays.gq;
    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    location / {
      proxy_pass http://ip.idays.gq:3000;
    }
  }
#WordPress
  server {
    listen 80;
    server_name blog.idays.gq;
  }
  server {
    listen 443 ssl http2;
    server_name blog.idays.gq;
    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    location / {
      proxy_pass http://ip.idays.gq:10000;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
  }
  # 文件服务器
  server {
    listen 443 ssl http2;
    server_name f.idays.gq;
    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    charset utf-8;  # 中文支持
    location / {
      root /usr/share/nginx/html/文件管理;  # 文件管理
      autoindex on;  # 开启索引功能
      autoindex_exact_size off;  # 关闭计算文件确切大小（单位bytes），只显示大概大小（单位kb、mb、gb）
      autoindex_localtime on;  # 显示本地时间
    }
  }
}
```
</details>
------

## 3、[安装WordPress](https://itlanyan.com/wordpress-one-click-script/)

```
#创建目录，创建配置文件
mkdir -p /home/wordpress /home/mysql && cd /home/wordpress && touch docker-compose.yml
```

```
version: '3'

services:

  wordpress:
    image: wordpress:latest
    container_name: wordpress
    restart: always
    ports:
      - 10000:80
    environment:
      WORDPRESS_DB_HOST: database
      WORDPRESS_DB_NAME: wordpress
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpress_password
    volumes:
      - /home/wordpress:/var/www/html
    links:
      - database

  database:
#    image: mysql
    image: arm64v8/mysql:latest
    container_name: mysql
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: root_password
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpress_password
    volumes:
      - /home/mysql:/var/lib/mysql
```

```
apt update && apt install -y curl
#方式1
bash <(curl -sL https://2i.gs/7uFN)
#方式2
wget https://raw.githubusercontent.com/tlanyan/Scripts/master/wordpress.sh && bash wordpress.sh
```

------

```
apt update && apt install -y curl
#方式1
bash <(curl -sL https://2i.gs/7uFN)
#方式2
wget https://raw.githubusercontent.com/tlanyan/Scripts/master/wordpress.sh && bash wordpress.sh
```

------

## 4、[AdGuardHome](https://github.com/AdguardTeam/AdGuardHome)[IP:3000]

```
docker run -d \
    --name AdguardHome \
    --restart unless-stopped \
    -v /home/adguardhome/work:/opt/adguardhome/work \
    -v /home/adguardhome/conf:/opt/adguardhome/conf \
    -p 53:53/tcp -p 53:53/udp \
    -p 100:3000/tcp \
    -p 853:853/tcp -p 853:853/udp \
    -p 5443:5443/tcp -p 5443:5443/udp \
    adguard/adguardhome
```
[========]
```
#纯DNS
-p 53:53/tcp -p 53:53/udp
#DHCP 服务器
-p 67:67/udp -p 68:68/tcp -p 68:68/udp
#管理面板与HTTPS/DNS-over-HTTPS服务器
-p 80:80/tcp -p 443:443/tcp -p 443:443/udp -p 3000:3000/tcp
#DNS-over-TLS服务器
-p 853:853/tcp
#DNS-over-QUIC服务器
-p 784:784/udp -p 853:853/udp -p 8853:8853/udp
# DNSCrypt 服务器
-p 5443:5443/tcp -p 5443:5443/udp
```


```
#安装脚本
apt-get install sudo && curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
```


[========]

<details>
<summary>AdGuardHome配置</summary>
```
.
#DNS地址
.
180.76.76.76
223.5.5.5
223.6.6.6
119.29.29.29
182.254.116.116
.
#广告拦截规则
.
#1、HalfLife，规则合并自 EasylistChina、EasylistLite、CJX’sAnnoyance 合并规则（几乎每天更新)
https://gitee.com/halflife/list/raw/master/ad.txt
2、ChinaList+EasyList
http://sub.adtchrome.com/adt-chinalist-easylist.txt
#3、xinggsf，乘风广告过滤规则 
https://gitee.com/xinggsf/Adblock-Rule/raw/master/rule.txt
.
#自定义屏蔽Youtube
.
/googleads.$~script,domain=~googleads.github.io
/pagead/lvz?
||google.com/pagead/
||static.doubleclick.net^$domain=youtube.com
||youtube.com/get_midroll_
||api.ad.xiaomi.com^$important
@@||github.com^$important
@@||ulogs.umengcloud.com^$important
@@||toblog.ctobsnssdk.com^$important
@@||ulogs.umeng.com^$important
@@||githubusercontent.com^$important
@@||*.google.com^$important
@@||*.pixivic.com^$important
```
</details>


------

## 5、[E5部署并搭建续签平台](https://hub.docker.com/r/hanhongyong/ms365-e5-renew-x)

```
docker run -d \
  --name ms365 \
  --restart=always \
  -p 1066:1066 \
  -e TZ=Asia/Shanghai \
  hanhongyong/ms365-e5-renew-x:arm

#初始密码123456
#修改密码
docker exec -it ms365 /bin/bash
apt-get update && apt-get install -y vim
cd Deploy && vim Config.xml
:set encoding=utf-8
```

[配置Azure](https://blog.csdn.net/qq_33212020/article/details/119747634)

<details>
<summary>配置AZ</summary>
```javascript
1点击登录 Azure或点击直接进入Azure应用注册，登录账号使用申请到的Microsoft 365 E5的管理员账户（账户名类似XXXX@YYYY.onmicrosoft.com格式）
2登录完成后点击右上角的“门户”按钮进入Azure管理中心，在搜索栏内输入“应用注册”，点击进入（若应用注册搜索不到请点击此处直接进入）。
3单击“新注册”按钮，配置应用。
应用名称随意写、注意可访问性选项选择最后一项、重定向URL暂时不填 、完成后点击注册
任何组织目录(任何 Azure AD 目录 - 多租户)中的帐户和个人 Microsoft 帐户(例如，Skype、Xbox)	
重定向 URI (可选),web
4先点击“概述”，然后点击“添加重定向URL”，进入重定向URL配置界面,复制应用程序(客户端)ID即为"客户端ID"。
5点击“添加平台”，再点击“移动和桌面应用程序”，继续勾选中第一个URL，最后点击底部的“配置”，该URL为“https://login.microsoftonline.com/common/oauth2/nativeclient”也可手动添加。配置。
6继续勾选中第一个URL，最后点击底部的“配置”，该URL为“https://login.microsoftonline.com/common/oauth2/nativeclient”也可手动添加。
7置应用程序的API权限
【委托的权限(用户登录)】类型的API
点击“API权限”-“添加权限”-“Microsoft Graph”-选择“委托的权限”->选择“委托的权限”-
>BookingsAppointment-BookingsAppointment.ReadWrite.All
>Calendars.Read-Read user calendars
>Contacts.Read-Read user contacts
>Directory.Read.All-Read directory data
>Files.Read.All-Read all files that user can access
>Files.ReadWrite.All-Have full access to all files user can access
>Group.Read.All-Read all groups
>MailboxSettings.Read-Read user mailbox settings
>Mail.Read-Read user mail
>Mail.Send-Send mail as a user
>Notes.Read.All-Read all OneNote notebooks that user can access
>People.Read.All-Read all users' relevant people lists
>Presence.Read.All-Read presence information of all users in your organization
>Sites.Read.All-Read items in all site collections
>Tasks.ReadWrite-Create, read, update, and delete user’s tasks and task lists
>User.Read.All-Read all users' full profiles
"添加权限"“代表XX授予管理员同意”
}
```
</details>

[Microsoft 365 develope](https://developer.microsoft.com/en-us/microsoft-365/profile)


```
wsng911@hotmail.com
2c3ca6d3-2f4e-448b-ba84-818a09887c0f
admin@solarday.onmicrosoft.com

wsng911@live.com
b3c86250-66cf-4017-b754-e6ff3bf5b308
admin@iiiday.onmicrosoft.com
```


------

## 6、[Freenom自动续期](https://github.com/luolongfei/freenom)

```
docker run -d --name freenom --restart always -v $(pwd):/conf -v $(pwd)/logs:/app/logs luolongfei/freenom
```

------

## 7、[PagerMaid-Pyro](https://t.me/PagerMaid_Modify/202)[IP:3333]

```
Docker 一键安装：
wget https://raw.githubusercontent.com/TeamPGM/PagerMaid-Pyro/development/utils/docker.sh -O docker.sh && chmod +x docker.sh && bash docker.sh
```

```
#APP api
https://my.telegram.org/
App api_id:
17742875
App api_hash:
7dfbcfa8a9669d0fb8f375c89cf2b90c
手机号：
+19102929613
```

------

## 8、[ChatGPT TG部署](https://github.com/yonggekkk/chatgpt-tg-bot-script)

```
bash <(curl -sSL https://gitlab.com/rwkgyg/chatgptbot/raw/main/chatgpt.sh)
#TG token
5802273018:AAF3J8JwEeQ2zFrm9TV0Db8ssDAMYm4m6vw
#chat API
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
```

------

## 9、ChatGPT WEB部署

```
docker run -d \
  --name ChatGPT \
  --restart=always \
  -p 3002:3000 \
  -e OPENAI_API_KEY="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" \
  -e CODE="shabusha" \
  yidadaa/chatgpt-next-web
```

```
#更新，删除后重装
docker rm -f ChatGPT
docker rmi yidadaa/chatgpt-next-web
```

```
#API
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
```

## 10、[vaultwarden](https://hub.docker.com/r/vaultwarden/server)

```
docker run -d --name vaultwarden -v /vw-data/:/data/ -p 9999:80 vaultwarden/server:latest
```

## 11、SearXNG

```
docker run -dit --name searxng -v $PWD/searxng:/etc/searxng -e TZ=Asia/Shanghai -p 8686:8080 --hostname searxng --restart always searxng/searxng:latest
```

------

## 12、[showdoc](https://www.showdoc.com.cn/help/65610)[IP:4999]
```
mkdir -p /home/showdoc
chmod  -R 777 /home/showdoc
docker run -d \
    --name showdoc \
    --user=root \
    --privileged=true \
    -p 4999:80 \
    -v /home/showdoc:/var/www/html/ \
    star7th/showdoc:arm-latest
#ARM版本：arm-latest AMD版本：last
```
## 13、TailScale
```
docker run -d \
  --name=tailscaled \
  --restart unless-stopped \
  -v /var/lib:/var/lib \
  -v /var/lib/tailscale:/var/lib/tailscale \
  -v /dev/net/tun:/dev/net/tun \
  --network=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --env TS_EXTRA_ARGS="--advertise-exit-node" \
  --env TS_STATE_DIR="/var/lib/tailscale" \
  tailscale/tailscale
```
## 14、Rainloop[10086]
```
docker run -d \
  --restart unless-stopped \
  --name rainloop \
  --log-opt max-size=2m \
  -p 10086:80 \
  -v /home/rainloop/data:/rainloop/data \
amwpfiqvy/rainloop
```
管理面板 http://YOUR-IP/?admin admin 12345
