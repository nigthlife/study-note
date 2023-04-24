<?php
header("Content-Type:text/html;charset=utf-8");
error_reporting(0);
highlight_file(__FILE__);
if (isset($_GET['wllm'])) {
    $wllm = $_GET['wllm'];
    $blacklist = [' ', '\t', '\r', '\n', '\+', '\[', '\^', '\]', '\"', '\-', '\$', '\*', '\?', '\<', '\>', '\=', '\`',];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $wllm)) {
            die("LTLT说不能用这些奇奇怪怪的符号哦！");
        }
    }
    if (preg_match('/[a-zA-Z]/is', $wllm)) {
        die("Ra's Al Ghul说不能用字母哦！");
    }
    echo "NoVic4说：不错哦小伙子，可你能拿到flag吗？";
    eval($wllm);
} else {
    echo "蔡总说：注意审题！！！";
}
