<?php
require_once('lib.php');
echo '<html>
<meta charset="utf-8">
<title>update</title>
<h2>这是一个未完成的页面，上线时建议删除本页面</h2>
</html>';
if ($_SESSION['login'] != 1) {
	echo "你还没有登陆呢！";
}
$users = new User();
$users->update();

if ($_SESSION['login'] === 1) {
	require_once("flag.php");
	echo $flag;
}
