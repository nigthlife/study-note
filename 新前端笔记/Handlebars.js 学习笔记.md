# Handlebars.js 学习笔记

## 0、前言

>   **首先Handlebars 是一种简单的 模板语言**

>   它使用模板和输入对象来生成HTML或者其他文本格式
>
>   它的模板看起来像常规的文本，但是它带有嵌入式的**Handlebars表达式**

>   Handlebars 表达式是一个 `{{`，一些内容，后跟一个 `}}`。执行模板时，这些表达式会被输入对象中的值所替换

### 安装

```html
<!-- Include Handlebars from a CDN -->
<script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
<script>
  // 编译模板
  var template = Handlebars.compile("Handlebars <b>{{doesWhat}}</b>");
  // 执行编译后的模板并将输出打印到控制台
  console.log(template({ doesWhat: "rocks!" }));
</script>
```

**npm或者yarn安装**

```sh
npm install handlebars
# 或者
yarn add handlebars


```

```js
// 然后通过 require 来使用 Handlebars
const Handlebars = require("handlebars");
const template = Handlebars.compile("Name: {{name}}");
console.log(template({ name: "张三" }));
```



## 1、语言的特性

### 1、基本表达式

```html
<html>
<head>

    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>
<body>
    
    <div id="context">按钮</div>
    
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
    	<p>{{firstname}} {{lastname}}</p>
    </script>
</body>

<script>
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;
    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);

    var data =  {
        firstname: "Yehuda",
        lastname: "Katz",
    }
    // 匹配并替换与之相对应的内容
    var context = template(data);

    // 输出内容到页面
    document.getElementById('context').innerHTML = context   
</script>
</html>
```

### 2、嵌入对象写法

```html
<html>
<head>
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>
<body>  
    <div id="context">按钮</div> 
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
    	{{person.firstname}} {{person.lastname}}
    </script>
</body>
<script>
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;
    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);

    var data =  {
      person: {
        firstname: "Yehuda",
        lastname: "Katz",
      },
    }
    // 匹配并替换与之相对应的内容
    var context = template(data);

    // 输出内容到页面
    document.getElementById('context').innerHTML = context   
</script>
</html>
```

### 3、上下文操作

>   内置的块助手代码 `each` 和 `with` 允许更改当前代码块的值

**`with`**：**使你可以访问对象属性的值**

```js
<html>
<head>
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>
<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{#with person}}
        {{firstname}} {{lastname}}
        {{/with}}
    </script>
</body>
<script>
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;
    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);

    var data = {
        person: {
            firstname: "Yehuda",
            lastname: "Katz",
        },
    }
    // 匹配并替换与之相对应的内容
    var context = template(data);

    // 输出内容到页面
    document.getElementById('context').innerHTML = context
</script>
</html>
```

`each` 迭代一个数组，可以通过 Handlebars 简单访问每个对象的属性

```js
<html lang="en">
<head>
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        <ul class="people_list">
            {{#each people}}
            <li>{{this}}</li>
            {{/each}}
        </ul>
    </script>
</body>
<script>
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;
    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);

    var data = {
        people: [
            "Yehuda Katz",
            "Alan Johnson",
            "Charles Jolley",
        ],
    }
    // 匹配并替换与之相对应的内容
    var context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context
</script>
</html>
```

### 4、自定义助手

>   通过调用 Handlebars.registerHelper 方法，可以从模板中的任何上下文中访问 Handlebars 助手代码

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>

    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        	<p>{{firstname}} {{loud lastname}}</p>
    </script>
</body>

<script>

    var data = {
        firstname: "Yehuda",
        lastname: "Katz",
    }

    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;

    Handlebars.registerHelper('loud', function (aString) {
        return aString.toUpperCase()
    })

    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);


    // 匹配并替换与之相对应的内容
    var context = template(data);

    // 输出内容到页面
    document.getElementById('context').innerHTML = context
</script>

</html>
```

**助手代码将当前上下文作为函数的 `this` 指针接收。**

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{#each people}}
            {{print_person}}        
        {{/each}}
    </script>
</body>
<script>
    var data = {
        people: [
            {
                firstname: "Nils",
                lastname: "Knappmeier",
            },
            {
                firstname: "Yehuda",
                lastname: "Katz",
            },
        ],
    }
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;

    Handlebars.registerHelper('print_person', function () {
        return this.firstname + ' ' + this.lastname
    })

    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);

    var context = template(data);

    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 5、块助手代码

>   有点像jsp后端手动拼html

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{#list people}}
            {{firstname}} {{lastname}}
        {{/list}}
    </script>
</body>
<script>
    var data = {
        people: [
            {
                firstname: "Nils",
                lastname: "Knappmeier",
            },
            {
                firstname: "Yehuda",
                lastname: "Katz",
            },
        ],
    }
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;

    Handlebars.registerHelper('list', function (items, options) {
        // 拼接两个属性值的内容
        const itemsAsHtml = items.map(item => "<li>" + options.fn(item) + "</li>");
        return "<ul>\n" + itemsAsHtml.join("\n") + "\n</ul>";
    })

    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);
    // 填充数据
    var context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context
</script>
</html>
```

### 6、HTML转义

>   因为它最初设计用于生成 HTML，所以 Handlebars 转义了`{{expression}}`. 
>
>   如果您不希望 Handlebars 转义某个值，请使用“triple-stash” `{{{`，

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        原始: {{{specialChars}}}
        html转义后: {{specialChars}}
    </script>
</body>
<script>
    var data = {
        specialChars: "& < > \" ' ` =" 
    }
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;

    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);
    // 填充数据
    var context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

**手动转义参数。**

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{bold text}}
    </script>
</body>
<script>
    var data = {
        text: "Isn't this great?"
    }
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;

    Handlebars.registerHelper("bold", function (text) {
        var result = "<b>" + Handlebars.escapeExpression(text) + "</b>";
        return new Handlebars.SafeString(result);
    });


    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);
    // 填充数据
    var context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 7、代码片段

>    Handlebars 代码片段通过创建共享模板允许代码复用。可以使用 `registerPartial` 方法

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{#each persons}}
            {{>person person=.}}
        {{/each}}
    </script>
</body>
<script>
    var data = {
        persons: [
            { name: "Nils", age: 20 },
            { name: "Teddy", age: 10 },
            { name: "Nelson", age: 40 },
        ],
    }
    // 首先获取script标签中的html代码内容
    var test = document.getElementById('test').innerHTML;

    Handlebars.registerPartial(
        "person",
        "{{person.name}} is {{person.age}} years old.<br>"
    )


    // 使用handlebars预编译一下
    var template = Handlebars.compile(test);
    // 填充数据
    var context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

## 2、各种表达式

### 1、路径表达式

>   Handlebars 同时支持一个已弃用的 `/` 语法

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        <p>{{person.lastname}} {{person.firstname}}</p>
        <p>{{person/firstname}} {{person/lastname}}</p>
    </script>
</body>
<script>
    var data = {
       person: {
            firstname: "Yehuda",
            lastname: "Katz",
        },
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;
    
    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 2、更改上下文

>   一些诸如 `#with` and `#each` 的助手代码使你能够操作嵌套的对象。
>
>   当你在路径中包含 `../` 时，Handlebars 将转回父级上下文
>
>   **也就是说当你一个对象中含有两个或者多个属性时，你在模板`#each`中定义了访问对象的第一个属性的内容**
>
>   **然后想在访问对象第一个属性的时候，去访问对象中的第二个属性那么就阔以使用`../属性名称`来获取第二个属性的值**

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{#each people}}
            {{../prefix}} {{firstname}}
        {{/each}}
    </script>
</body>
<script>
    var data = {
        people: [
            { firstname: "Nils" },
            { firstname: "Yehuda" },
        ],
        prefix: "Hello",
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 3、文字

>   除了以下字符，标识符可以是任何 Unicode 文本：
>
>   *Whitespace* `!` `"` `#` `%` `&` `'` `(` `)` `*` `+` `,` `.` `/` `;` `<` `=` `>` `@` `[` `\` `]` `^` ``` `{` `|` `}` `~`
>
>   除此之外，`true`, `false`, `null` 和 `undefined` 只允许在路径表达式的开头出现。

>   JavaScript 样式的字符串如 `"` 和 `'` 也可用于替代 `[`

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{!-- wrong: {{array.0.item}} --}}
        <p>correct: array.[0].item: {{array.[0].item}}</p>
        
        {{!-- wrong: {{array.[0].item-class}} --}}
        <p>correct: array.[0].[item-class]: {{array.[0].[item-class]}}</p>
        
        {{!-- wrong: {{./true}}--}}
        <p>correct: ./[true]: {{./[true]}}</p>
    </script>
</body>
<script>
    var data = {
        array: [
            {
                item: "item1",
                "item-class": "class1",
            },
        ],
        true: "yes",
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 4、html转义

**模板中写入**

```js
raw: {{{specialChars}}}
html-escaped: {{specialChars}}
```

**再将如下特殊的输入传入模版**

```js
{ specialChars: "& < > \" ' ` =" }
```

**使用 `{{{` 会输出原始结果。否则将会输出 HTML 转义之后的结果**

```js
raw: & < > " ' ` =
html-escaped: &amp; &lt; &gt; &quot; &#x27; &#x60; &#x3D;
```

### 5、具有多个参数的助手代码

>   此例子中，Handlebars 将把两个参数传递给 link 助手代码：字符串 See Website 与从下面提供的 people 输入对象中的 people.value。
>
>   使用同一助手代码，但使用基于 `people.text` 的值的动态文本：

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{link "See Website" url}}
        {{link people.text people.url}}
    </script>
</body>
<script>
    var data = {
        url: "https://peekaboo.show/",
        people: {
            firstname: "Yehuda",
            lastname: "Katz",
            url: "https://peekaboo.show/",
            text: "See Website",
        }
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    Handlebars.registerHelper("link", function (text, url) {
        var url = Handlebars.escapeExpression(url),
            text = Handlebars.escapeExpression(text)

        // {{link "See Website" url}} 被替换成了一个 a标签，See Website成了a标签的内容
        return new Handlebars.SafeString("<a href='" + url + "'>" + text + "</a>");
    });

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 6、 字面量参数

>   帮助代码调用亦可含字面量，作为参数抑或是 Hash 参数。支持的字面量有数字、字符串、`true`, `false`, `null` 及 `undefined`：

**进度条演示**

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{progress "Search" 10 false}}<br>
        {{progress "Upload" 90 true}}<br>
        {{progress "Finish" 100 false}}<br>
    </script>
</body>
<script>
    var data = {

    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    // 加载进度条演示
    Handlebars.registerHelper('progress', function (name, percent, stalled) {
        console.log(name);
        console.log(percent);
        console.log(stalled);
        var barWidth = percent / 5
        var bar = "********************".slice(0, barWidth)
        return bar + " " + percent + "% " + name + " " + (stalled ? "stalled" : "")
    })

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

#### 1、含有 Hash 参数的助手代码

Handlebars 提供了额外的元数据，例如 Hash 参数来作为助手代码的最后一个参数。

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        {{link "See Website" href=person.url class="person"}}
    </script>
</body>
<script>
    var data = {
        person: {
            firstname: "Yehuda",
            lastname: "Katz",
            url: "https://peekaboo.show/",
        },
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    Handlebars.registerHelper("link", function (text, options) {

        // text为标签内的文本内容
        console.log(text);
        // options有很多可操作的对象属性
        console.log(options);

        var attributes = [];

        Object.keys(options.hash).forEach(key => {
            var escapedKey = Handlebars.escapeExpression(key);
            var escapedValue = Handlebars.escapeExpression(options.hash[key]);
            attributes.push(escapedKey + '="' + escapedValue + '"');
        })
        var escapedText = Handlebars.escapeExpression(text);

        var escapedOutput = "<a " + attributes.join(" ") + ">" + escapedText + "</a>";
        return new Handlebars.SafeString(escapedOutput);
    });

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

#### 2、助手代码和属性查找时同名情况

>   如果助手代码注册时的名称和一个输入的属性名重复，则**助手代码的优先级更高**。
>
>   如果你想使用输入的属性，请在其名称前加 `./` 或 `this.`。（或是已弃用的 `this/`。）

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="https://cdn.jsdelivr.net/npm/handlebars@latest/dist/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->
    <script id="test" type="text/x-handlebars-template">
        helper: {{name}}<br>
        data: {{./name}} or {{this/name}} or {{this.name}}
    </script>
</body>
<script>
    var data = {
        name: "Yehuda"
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    Handlebars.registerHelper('name', function () {
        return "Nils"
    })

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

#### 3、子级表达式

>   可以在单个 Mustache 模板中调用多个助手代码，并且将内部助手代码调用的返回值作为 外部助手代码的参数传递

```js
{{outer-helper (inner-helper 'abc') 'def'}}
```

>   上例中，`inner-helper` 会被调用并带有字符串参数 `'abc'`，
>
>   同时不论 `inner-helper` 返回了什么，
>
>   返回值都将被作为第一个参数 传递给 `outer-helper`（同时 `'def'` 会作为第二个参数传递）

### 4、空格处理

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="./js/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->

    <script id="test" type="text/x-handlebars-template">
        {{#each nav }}
        <a href="{{url}}">
            {{~#if test}} 
            {{title}}
            {{~^~}}
            Empty
            {{~/if~}}
        </a>
        {{~/each}}
        <!-- 渲染结果：<a href="foo">bar</a><a href="bar">Empty</a> -->
        -----------------------------------<br>

        {{#each nav}}
        <a href="{{url}}">
            {{#if test}}
            {{title}}
            {{^}}
            Empty
            {{/if}}
        </a>
        {{~/each}}
        <!-- 渲染结果 <a href="foo">
                        bar
                        </a>
                        <a href="bar">
                        Empty
                        </a>
        -->
    </script>
</body>
<script>
    var data = {
        nav: [{ url: "peekaboo.show", test: true, title: "bar" }, { url: "peekaboo.show" }]
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;


    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

## 3、内置的助手代码

### 1、#if

>   **设置 `includeZero=true` 可将 `0` 视为非空值**

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="./js/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->

    <script id="test" type="text/x-handlebars-template">
        <div class="entry">
            {{#if author}}
            <h1>{{firstName}} {{lastName}}</h1>
            {{else}}
            <h1>Unknown Author</h1>
            {{/if}}
            <br>
            {{#if 0 includeZero=true}}
            <h1>这里会渲染</h1>
            {{/if}}
        </div>
    </script>
</body>
<script>
    var data = {
        author: false,
        firstName: "Yehuda",
        lastName: "Katz",
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

>   使用函数进行if判断值为`null`和`undefined`

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="./js/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->

    <script id="test" type="text/x-handlebars-template">
        <div class="entry">
        {{#if (isdefined value1)}}
        	true
        {{else}}
        	false
        {{/if}}
        {{#if (isdefined value2)}}
        	true
        {{else}}
        	false
        {{/if}}
        </div>
    </script>
</body>
<script>
    var data = {
        value1: {}
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    Handlebars.registerHelper('isdefined', function (value) {
        return value !== undefined;
    });

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 2、#unless

>    **`unless` 助手代码与 `if` 助手代码相反，如果表达式返回 false 则将渲染代码块**

### 3、#each

>   `each` 助手代码遍历列表。在块内，使用 `this` 来引用被迭代的元素
>
>   **也可以写一个`{{else}}`该代码块将只会在列表为空时显示**

>   可以选择通过 `{{@index}}` 引用当前循环的索引
>
>   可以使用 `{{@key}}` 引用当前的键名
>
>   还可以使用 [`@first`](https://www.handlebarsjs.cn/api-reference/data-variables.html#first) 和 [`@last`](https://www.handlebarsjs.cn/api-reference/data-variables.html#last) 变量记录迭代的第一项和最后一项
>
>   嵌套的每个块都可以通过基于深度的路径来访问迭代变量。例如，要访问父级的索引，可以使用 `{{@../index}}`

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="./js/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->

    <script id="test" type="text/x-handlebars-template">
        <ul class="people_list">
            {{#each people}}
            <li>{{@index}}:{{this}}</li>
            {{/each}}
            <br>
            {{#each person}} {{@key}}: {{this}}<br> {{/each}}
        </ul>
    </script>
</body>
<script>
    var data = {
        people: [
            "Yehuda Katz",
            "Alan Johnson",
            "Charles Jolley",
        ],
        person: {
            firstname: "Yehuda",
            lastname: "Katz",
            url: "https://peekaboo.show/",
            text: "See Website",
        } 
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 4、#with

==取别名写法==

>   `{{#with city as | ad |}}`：也就是给city取一个别名，下面访问city可以使用ad代替
>
>   ` {{#with ad.location as | loc |}}`：也可以单独给对象中的某个属性取别名

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="./js/handlebars.js"></script>
</head>

<body>
    <div id="context">按钮</div>
    <!-- 需要运用的模板的地方需要用script标签包裹起来 -->

    <script id="test" type="text/x-handlebars-template">
        {{#with city as | ad |}}
            {{#with ad.location as | loc |}}
                {{ad.name}}: {{loc.north}} {{loc.east}}
            {{/with}}
        {{/with}}
    </script>
</body>
<script>
    var data = {
        city: {
            name: "San Francisco",
            summary: "San Francisco is the <b>cultural center</b> of <b>Northern California</b>",
            location: {
                north: "37.73,",
                east: -122.44,
            },
            population: 883305,
        },
    }
    // 首先获取script标签中的html代码内容
    const test = document.getElementById('test').innerHTML;

    // 使用handlebars预编译一下
    const template = Handlebars.compile(test);
    // 填充数据
    const context = template(data);
    // 输出内容到页面
    document.getElementById('context').innerHTML = context

</script>

</html>
```

### 5、lookup

>   `lookup` 允许使用 Handlebars 变量进行动态的参数解析

