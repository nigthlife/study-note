<?php
error_reporting(0);
highlight_file(__FILE__);

function check($input){
    if(preg_match("/'| |_|php|;|~|\\^|\\+|eval|{|}/i",$input)){
        // if(preg_match("/'| |_|=|php/",$input)){
        die('hacker!!!');
    }else{
        return $input;
    }
}

// 是否是数组,数组就进入递归，不是直接进入过滤，并返回过滤后的值
function waf($input){
    
  if(is_array($input)){
      foreach($input as $key=>$output){
          $input[$key] = waf($output);
      }
  }else{
      $input = check($input);
  }
}

// sandbox+MD5加密IP地址+/
$dir = 'sandbox/' . md5($_SERVER['REMOTE_ADDR']) . '/';

// 文件夹不存在创建
if(!file_exists($dir)){
    mkdir($dir);
}

// 根据action的值
switch($_GET["action"] ?? "") {
    // 输出文件路径
    case 'pwd':
        echo $dir;
        break;
    // 上传文件
    case 'upload':
        $data = $_GET["data"] ?? "";
        waf($data);
        file_put_contents("$dir" . "index.php", $data);
}
?>