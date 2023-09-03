<?php

function waf($filename){
    $black_list = array("ph", "htaccess", "ini");

    # 获取文件后缀名
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    foreach ($black_list as $value) {
        if (stristr($ext, $value)){
            return false;
        }
    }
    return true;
}

if(isset($_FILES['file'])){
    # 获取上传的文件
    $filename = urldecode($_FILES['file']['name']);
    
    # tmp_name: 是该文件在服务器上临时存储的路径和文件名
    # 获取上传文件内容和临时存储路径
    $content = file_get_contents($_FILES['file']['tmp_name']);
    
    if(waf($filename)){
        # 写入文件，将 $content 的内容写入 $filename 中
        file_put_contents($filename, $content);
    } else {
        echo "Please re-upload";
    }
} else{
    highlight_file(__FILE__);
}