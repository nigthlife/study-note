http://1e18d24b-1b19-4769-8353-245409ca5cdb.node4.buuoj.cn:81/sandbox/2eeed2f9aeae6311b507ada8fb98809e/ls%20/%7C
<?php

    // 判断是否存在HTTP_X_FORWARDED_FOR
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // 获取ip地址
        $http_x_headers = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $_SERVER['REMOTE_ADDR'] = $http_x_headers[0];
    }
    // 输出ip地址值
    echo $_SERVER["REMOTE_ADDR"];

    $sandbox = "sandbox/" . md5("orange" . $_SERVER["REMOTE_ADDR"]);
    @mkdir($sandbox);
    @chdir($sandbox);

    // 将url转换为shell参数然后返回执行结果
    $data = shell_exec("GET " . escapeshellarg($_GET["url"]));
    // 获取文件路径信息
    $info = pathinfo($_GET["filename"]);

    // 将文件名中的【.】替换为空
    $dir  = str_replace(".", "", basename($info["dirname"]));

    // 创建文件夹并进入
    @mkdir($dir);
    @chdir($dir);

    // 把data中的数据写入info中
    @file_put_contents(basename($info["basename"]), $data);
    highlight_file(__FILE__);

[HITCON 2017]SSRFme
flag{dd1983a7-0904-4576-a07e-495715563539}