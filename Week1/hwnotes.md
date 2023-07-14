# HWnotes

> 近来准备HW，积累一些问题，既为自己也为他人。

[TOC]

## 1.使用过哪些厂商的设备？

这里如实回答即可。设备有奇安信天眼啥的，如果没用过，看资料。

奇安信天眼一些规则：

> 模糊搜索：使用问号（?）表示单个字符的通配符搜索，使用星号（*）表示多个字符的通配符搜索。 多字符的通配符搜索寻找零个或多个字符。
>
> attack_sip 攻击者IP alarm_sip 受害者IP attack_type攻击类型
>
> 日志检索中 AND 运算符（AND、&& 或 +） OR 运算符（OR 或 ||）NOT 运算符（NOT、! 或 -）
>
> 搜索源ip和目标ip命令： 源IP: sip="" ，目标IP: dip=""

## 2.一个登录页面渗透思路

这里可以根据Vulnhub里的一些靶机来说。比如DC-1的思路就是：

首先先进行信息收集。例如使用nmap对这个域名进行扫描，看看哪些端口是开放的，然后开放的端口分别运行着什么服务。

之后在登录界面，可以使用一些浏览器插件（wappalyzer）或者看页面来判断使用了什么框架。这一步可以先试试一些简单的SQL注入。如果注入无果，启动msfconsole来查询此框架此版本有什么漏洞。

之后尝试一些里面的exp。如果利用成功的话，获取shell后，先查看一下自己的权限。之后在靶机继续进行收集，比如在配置文件里找到一些有关数据库的信息（账号密码），若找到，则进入数据库查看管理员账户的信息来尝试拿到网站的后台。

如果有提权的需要的话，可以考虑suid提权。一些有suid权限的程序在运行时可以执行shell指令，导致root权限的一个获取。

（这是初级渗透，基于DC-1靶机改编。至于更高级的还得等我继续学习……）

## 3.weblogic常见漏洞

> WebLogic弱口令漏洞

顾名思义，管理员会使用常见的弱口令。爆破可以拿到。

> Weblogic任意文件上传CVE-2018-2894漏洞

 进入未经授权的上传界面后，将“通用”下的“当前工作目录”路径设置为ws_utc应用的静态文件css目录，访问这个目录是无需权限的。上传一个jsp木马，抓包，点击提交，为什么要抓包呢，因为包里面有一个时间戳，连接木马的时候要用上。

> WebLogic XMLDecoder反序列化漏洞（CVE-2017-3506）
>
> WebLogic XMLDecoder反序列化漏洞（CVE-2017-10271）

Weblogic的WLS Security组件对外提供webservice服务，其中使用了XMLDecoder来解析用户传入的XML数据，在解析的过程中出现反序列化漏洞，导致可执行任意命令。攻击者发送精心构造的xml数据甚至能通过反弹shell拿到权限。

## 4.tomcat常见漏洞

> CVE-2017-12615任意文件上传

CVE-2017-12615由于配置不当，可导致任意文件上传，由于配置不当，conf/web.xml中的readonly设置为false，可导致用PUT方法上传任意文件，但限制了jsp后缀的上传。

利用：抓包，修改请求方式为PUT，并绕过后缀限制。

> CVE-2020-1938 AJP文件包含漏洞

CVE-2020-1938为Tomcat AJP文件包含漏洞，由于Tomcat AJP协议本身的缺陷，攻击者可以通过Tomcat AJP connector可以包含Webapps目录下的所有文件。

## 5.shiro550/721的特征，区别，以及721的利用条件

> shiro-550

Apache Shiro框架提供了记住密码的功能（RememberMe），用户登录成功后会生成经过加密并编码的cookie。在服务端对rememberMe的cookie值，先base64解码然后AES解密再反序列化，就导致了反序列化RCE漏洞。

**版本小于1.2.4**

Payload产生的过程：命令=>序列化=>AES加密=>base64编码=>RememberMe Cookie值
在整个漏洞利用过程中，比较重要的是AES加密的密钥，如果没有修改默认的密钥那么就很容易就知道密钥了,Payload构造起来也是十分的简单。

> shiro-721

由于shiro通过 AES-128-CBC 模式加密的rememberMe字段存在问题，用户可通过Padding Oracle 加密生成的攻击代码来构造恶意的rememberMe字段，并重新请求网站，进行反序列化攻击，最终导致任意代码执行。

**版本小于1.4.2**

> 区别

Shiro550使用已知`密钥碰撞`，只要有足够密钥库（条件较低），不需要Remember Cookie

Shiro721的aes keyy由系统随机生成，可使用登录后rememberMe去爆破正确的key值，即利用有效的RememberMe Cookie作为Padding Oracle Attack的前缀，然后精心构造 RememberMe Cookie 值来实现反序列化漏洞攻击，难度高。

**特征判断**：返回包中包含rememberMe=deleteMe字段。

请求包Cookie的rememberMe中会存在AES+base64加密的一串java反序列化代码。

返回包中存在base64加密数据，该数据可作为攻击成功的判定条件。

## 6.MySQL和SQL server提权

> MySQL

**必要条件**：

1. **具有MySQL的root权限，且MySQL以system权限运行。**
2. **具有执行SQL语句的权限。**

方式：

- udf提权
- mof提权
- 启动项提权

mof提权：

**原理**：利用了`C:\Windows\System32\wbem\MOF`目录下的`nullevt.mof`文件，利用该文件每分钟会去执行一次的特性，向该文件中写入cmd命令，就会被执行。

**利用条件**：

1. 只使用于windows系统，一般低版本系统才可以用，比如`xp`、`server2003`

2. 对`C:\Windows\System32\wbem\MOF`目录有读写权限

3. 可以找到一个可写目录，写入mof文件

**补救措施**

当发现服务器被使用mof提权，解决继续执行系统命令的方法：

1. 先停止winmgmt服务：`net stop winmgmt`
2. 删除文件夹：`C:\Windows\System32\wbem\Repository`
3. 再重新启动winmgmt服务：`net start winmgmt`

UDF提权：

**原理**：UDF(User Defined Funtion)用户自定义函数，通过添加新的函数，对mysql服务器进行功能扩充。

**利用条件**：

如果mysql版本大于5.1，udf.dll文件必须放置在mysql安装目录的`MySQL\Lib\Plugin\`文件夹下，该目录默认是不存在的，需要使用webshell找到mysql的安装目录，并在安装目录下创建`MySQL\Lib\Plugin\`文件夹，然后将udf.dll导入到该目录。

如果mysql版本小于5.1，udf.dll文件在windows server 2003下放置于`c:/windows/system32/`目录，在windows server 2000下放置在`c:/winnt/system32/`目录。

掌握mysql数据库的root账户，从而拥有对mysql的insert和delete权限，以创建和抛弃函数。

拥有可以将udf.dll写入相应目录的权限。

启动项提权：

利用MySQL，将后门写入开机启动项。同时因为是开机自启动，在写入之后，需要重启目标服务器，才可以运行。

## 7.EDR和杀软的区别

杀软基于静态特征判断是否有危险。EDR可以联动其他设备，统一管理，而且存在微隔离。EDR除了基于静态特征，也可以根据软件判断是否攻击。

## 8.SSH加固思路

更换端口，使用SSHv2，禁止root登录，禁止密码、使用密钥登录，设置黑白名单，禁用不使用的身份验证方法

## 9.Windows应急排查思路

见[这里](https://bypass007.github.io/Emergency-Response-Notes/Summary/)，整理的很到位。

## 10.冰蝎流量特征

#### 2.0

1. 十几个User-Agent头，每次请求时会随机选择其中的一个。如果发现一个ip的请求头中的user-agent在频繁变换，可能就是冰蝎
2. Accept值每个阶段都一样

#### 3.0

1. content-type字段常见为application/octet-stream
2. 16个User-Agent头，每次请求时会随机选择其中的一个。如果发现一个ip的请求头中的user-agent在频繁变换，可能就是冰蝎
3. 长连接
4. 较长的base64编码请求包

#### 4.0

1. 弱特征
   1. Content-type: Application/x-www-form-urlencoded
   2. Accept: application/json, text/javascript
2. 10种User-Agent,每次连接shell时会随机选择一个进行使用
3. 本地端口在49700左右，每连接一次，每建立一次新的连接，端口就依次增加
4. 默认使用长连接，请求头和响应头都有Connection: Keep-Alive
5. 默认连接密码rebeyond，密钥为连接密码32位md5值的前16位

## 11.SQL注入常见种类

> 报错注入

函数：floor()、updatexml()、extractvalue()

> 布尔盲注

函数：length()、substr()、ascii()

> 时间盲注

函数：sleep()

## 12.SQL注入防范思路

- **代码层防止sql注入攻击的最佳方案就是sql预编译**

- **规定数据长度，能在一定程度上防止sql注入**

- **严格限制数据库权限，能最大程度减少sql注入的危害**

- **过滤参数中含有的一些数据库关键词**

- **避免直接响应一些sql异常信息，sql发生异常后，自定义异常进行响应**

## 13.宽字节注入原理

宽字节注入时利用mysql的一个特性，使用GBK编码的时候，会认为两个字符是一个汉字。

比如%27可能会被过滤，但是%df%27会被认为是汉字，做到绕过。

**防御**：使用`mysql_set_charset(GBK)`指定字符集，使用`mysql_real_escape_string`进行转义。

## 14.SQL盲注一条语句查表结构（不用脚本）

dnslog外带。

DNSlog注入，原理大致为：当我们输入域名时，会向DNS服务器解析获取IP在通过IP访问，在这过程中DNS服务器会产生对域名请求解析的日志，比如此时存在一个域名为summer.com，要使用的payload为`whoami`.summer.com，就可以通过DNS解析日志来获取到主机名。

## 15.目录扫描过WAF

- 针对扫描速度过快，我们可以采用延时扫描，代理池,伪造ua的方法来进行绕过

先用延时扫描举例，代理池绕过,伪造ua的方法下面会提

比如说sqlmap中的delay参数

```
python sqlmap.py -u xxx.xxx.com --delay 2
```

通过delay参数，来延时扫描绕过cc防护，这时有小伙伴就说我用了delay参数啊，但是还是被ban了(这里假设是扫描速度过快导致)，那肯定是延时时间不够，就拿阿里云服务器做例子，阿里云服务器延时2秒被ban，延时2.5秒被ban，只有延时3秒才可以绕过。

- 针对扫描器指纹被waf修改，可以修改UA头,伪造模拟真实用户，使得扫描器指纹改变，让waf识别不出来

在ua头这里，建议大家选择爬虫引擎的ua头，因为有些网站考虑到自身流量的问题，希望网站被爬虫引擎收录，而爬虫引擎的扫描速度自然也是极快的，为了防止爬虫引擎被ban，有些waf(某狗)就会将爬虫引擎设置在白名单内，此时我们伪造成爬虫引擎的ua头，就可以成功地绕过cc防护和扫描器指纹，一举两得。

## 16.报错注入常见函数

**定义**：

SQL报错注入基于报错的信息获取，虽然数据库报错了，当我们已经获取到我们想要的数据。例如在增加删除修改处尝试(insert/update/delete)。

**常见函数**：

updatexml():是mysql对xml文档数据进行查询和修改的xpath函数
extractvalue()：是mysql对xml文档数据进行查询的xpath函数
floor():mysql中用来取整的函数
exp():此函数返回e(自然对数的底)指数X的幂值

字符串连接函数，截取，数学函数。

## 17.钓鱼邮件防范思路

1. 邮件内容涉及域名、IP均都应该进行屏蔽
2. 对访问钓鱼网站的内网IP进行记录，以便后续排查溯源可能的后果

反制：对邮件内的链接进行查询，whois，天眼ioc，附件在沙盒进行分析

1. 根据钓鱼邮件发件人进行日志回溯
2. 通知已接收钓鱼邮件的用户进行处理
   1. 删除钓鱼邮件
   2. 系统改密
   3. 全盘扫毒

## 18.Windows中CS排查思路
CS流量特征：

1. 下发指令：请求头中有id=
2. UA头：4.0版本的UA头是固定的，4.5及以上则会随机生成
3. 心跳包特征：间隔一定时间就会通信，请求包数据长度固定
4. ja3和ja3s：ja3和操作系统有关，ja3s和三次握手有关

## 19.后台getshell思路

**利用文件上传漏洞，找文件上传处想办法上传php文件。**

一些网站在设置可以允许修改上传的文件类型则直接添加php

有时候会还有检测是否为php文件，可以通过文件名变形，大小写，双写等形式绕过，只要是黑名单的都比较好绕过

很多cms还有.hatccess文件禁止访问或者执行这个目录下的文件的情况

这种情况直接上传一个.hatccess文件覆盖这个，让其失效。

或者上传不重命名的话上传../../shell.php 传到其他不被限制访问的目录

或者找任意文件删除漏洞把.htaccess文件删除

**zip解压getshell**

这个再系统升级或者插件安装的地方很多都有这个问题。上传shell.php在压缩包中，上传系统升级时会解压缩，那么就可以getshell

**数据库备份getshell**

## 20.Windows日志4625和4720是什么

4625：成功，4720：创建用户

日志目录：windows/System32/winevt/Logs

系统日志、安全日志、应用程序日志

事件查看器

事件IP：

>  4624----登录成功
>
>  4625----登录失败
>
>  4634----注销成功
>
>  4647----用户启动的注销，当⽤户远程登陆，并注销时，会发⽣此事件
>
>  4672----使用管理员进行登录
>
>  4720----新建用户
>
>  4724----更改账户密码
>
>  4726----删除⽤户

登录类型：

> 2----交互式登录
>
> 3----网络
>
> 4----批处理
>
> 5----服务启动（服务登录）
>
> 6----不支持
>
> 7----解锁
>
> 8----网络明文（IIS服务器登录验证）
>
> 10----远程交互
>
> 11----缓存域证书登录

## 21.Windows应急响应工具推荐

- Autoruns 启动项查看工具
- ProcessExplorer 进程查看工具
- ProcessMonitor 进程实时监控
- TCPview 网络连接查看工具
- D盾 Webshell查杀
- Everything 搜索工具

## 22.说一次应急响应的经历

见[这里](https://bypass007.github.io/Emergency-Response-Notes/Summary/)，整理的很到位。

## 23.说一次渗透中挖到的漏洞

自己打vulnhub靶机。

## 24.任意文件上传的跳过

![2023-7-13-11-19-41-20200814140212636.png](https://frist-2022-11-12.oss-cn-hangzhou.aliyuncs.com/img/2023-7-13-11-19-41-20200814140212636.png)

## 25.struts2特征

基于java开发的框架，大多数是远程命令执行

url中会出现的特征：`.action`

请求头中有id=，context

payload解码后有%和{ }

## 26.哥斯拉特征

1. 请求包含pass=
2. user-agent,如果不修改的话会返回使用的jdk信息
3. Accept为text/html, image/gif, image/jpeg
4. 请求包的Cookie中最后出现分号
5. 响应包数据：md5前十六位+base64+md5后十六位

## 27.菜刀特征

1. payload在请求体中，采用url编码+base64编码，payload部分是明文传输
2. payload中有eval或assert、base64_decode这样的字符

## 28.蚁剑特征

1. 加密后参数名以_0x开头，是base64加密
2. 请求体只是经过 url 编码，特征为ini_set("display_errors","0")

