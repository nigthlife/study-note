<?php
    $files = scandir('./');
    // 遍历当前目录文件
    foreach ($files as $file) {
        if (is_file($file)) {

            // 当文件名称不等于index.php时删除文件
            if ($file !== "index.php") {
                unlink($file);
            }
        }
    }
    // 传入两个参数
    if (!isset($_GET['content']) || !isset($_GET['filename'])) {
        highlight_file(__FILE__);
        die();
    }

    $content = $_GET['content'];
    // 忽略大小写判断指定是否存在content中
    if (stristr($content, 'on') || stristr($content, 'html') || stristr($content, 'type') || stristr($content, 'flag') || stristr($content, 'upload') || stristr($content, 'file')) {
        echo "Hacker";
        die();
    }
    $filename = $_GET['filename'];
    // 文件名称只能为字母+点
    if (preg_match("/[^a-z\.]/", $filename) == 1) {
        echo "Hacker";
        die();
    }
    $files = scandir('./');
    foreach ($files as $file) {
        // 判断给定文件名是否为一个正常的文件
        if (is_file($file)) {
            if ($file !== "index.php") {
                unlink($file);
            }
        }
    }
    // 输出
    file_put_contents($filename, $content . "\nHello, world");
?>

<!-- 
    总结：可以写入文件，就是会限制文件为index.php
    可以考虑使用.htaccess 文件
        优点就是：不需要重启服务器，也不需要管理员权限
 -->