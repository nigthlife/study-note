



### 1、添加代码高亮

>   直接在后台的 header、footer中注入

```html
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.28.0/themes/prism-tomorrow.min.css" integrity="sha512-vswe+cgvic/XBoF1OcM/TeJ2FW0OofqAVdCZiEYkd6dwGXthvkSFWOoGGJgS2CW70VK5dQM5Oh+7ne47s74VTg==" crossorigin="anonymous" referrerpolicy="no-referrer" />
```

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.28.0/components/prism-core.min.js" integrity="sha512-9khQRAUBYEJDCDVP2yw3LRUQvjJ0Pjx0EShmaQjcHa6AXiOv6qHQu9lCAIR8O+/D8FtaCoJ2c0Tf9Xo7hYH01Q==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.28.0/plugins/autoloader/prism-autoloader.min.js" integrity="sha512-fTl/qcO1VgvKtOMApX2PdZzkziyr2stM65GYPLGuYMnuMm1z2JLJG6XVU7C/mR+E7xBUqCivykuhlzfqxXBXbg==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
```

### 2、添加文章目录

>   编辑 **content/themes/正在使用的主题/default.hbs**文件，在`{{ghost_head}}`中添加css文件

```html
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/tocbot/4.12.3/tocbot.css">

<style>
.gh-content {
    position: relative;
 }

.gh-toc > .toc-list {
    position: relative;
}

.toc-list {
    overflow: hidden;
    list-style: none;
}

@media (min-width: 1300px) {
     .gh-sidebar {
        position: absolute; 
        top: 0;
        bottom: 0;
        margin-top: 4vmin;
        grid-column: wide-start / main-start; /* Place the TOC to the left of the content */
    }
   
    .gh-toc {
        position: sticky; /* On larger screens, TOC will stay in the same spot on the page */
        top: 4vmin;
    }
}

.gh-toc .is-active-link::before {
    background-color: var(--ghost-accent-color); /* Defines TOC   accent color based on Accent color set in Ghost Admin */
} 
</style>
```

>   **移动到最底部的`{{ghost_foot}}`上面添加js文件**

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/tocbot/4.12.3/tocbot.min.js"></script>

{{! Initialize Tocbot after you load the script }}
<script>
    tocbot.init({
        // Where to render the table of contents.
        tocSelector: '.gh-toc',
        // Where to grab the headings to build the table of contents.
        contentSelector: '.gh-content',
        // Which headings to grab inside of the contentSelector element.
        headingSelector: 'h1, h2, h3, h4',
        // Ensure correct positioning
        hasInnerContainers: true,
    });
</script>
```

>   **在同目录中的`post.hbs`文件中的`{{content}}`上面添加代码**

```html
<aside class="gh-sidebar"><div class="gh-toc"></div></aside> {{! The TOC will be inserted here }}
```



### 3、添加阅读时间

>   **编辑content/themes/正在使用的主题/post.hbs**文件**,
>   在`<header>`标签中的`<span>`标签中的`<time>`标签中的`{{data}}`后面添加

```
    {{reading_time minute="Only a minute" minutes="阅读大约需要 % 分钟"}}
```

### 4、添加阅读进度条

>   **编辑content/themes/正在使用的主题/post.hbs**文件**
>   在`{{!< default}}`的后面添加代码

```html
<progress class="reading-progress" value="0" max="100" aria-label="Reading progress"></progress>
```

>   然后在Code Injection → Site Header中，添加以下代码

```html
<style>
.reading-progress {
  position: fixed;
  top: 0;
  z-index: 999;
  width: 100%;
  height: 5px; /* Progress bar height */
  background: #c5d2d9; /* Progress bar background color */
  -webkit-appearance: none;
     -moz-appearance: none;
          appearance: none; /* Hide default progress bar */
}

.reading-progress::-webkit-progress-bar {
  background-color: transparent;
}

.reading-progress::-webkit-progress-value {
  background: var(--ghost-accent-color); /* Progress bar color */
}
</style>
```

>   使进度条动态化
>   **编辑content/themes/正在使用的主题/default.hbs**文件**
>   然后在`{{ghost_foot}}`的上面添加如下代码

```html
{{#is "post"}}
  <script>
    const progressBar = document.querySelector('.reading-progress');

    function updateProgress() {
      const totalHeight = document.body.clientHeight;
      const windowHeight = document.documentElement.clientHeight;
      const position = window.scrollY;
      const progress = position / (totalHeight - windowHeight) * 100;
      progressBar.setAttribute('value', progress);
      requestAnimationFrame(updateProgress);
    }

    requestAnimationFrame(updateProgress);
  </script>
{{/is}}
```

### 5、更改页面宽度

>    编辑 **content/themes/正在使用的主题/assets/built/screen.css**文件

```java
# 搜索
min(var(--content-width,720px)
- var(--content-width, 720px))/2)) [结果为2个，修改后面那个]
var(--container-width, 1200px)	[结果有3个，修改中间那个]

# 替换为如下
min(var(--content-width,1000px) （文章最小显示宽度【原来720px】）
- var(--content-width, 1000px))/2)) 
var(--container-width, 1250px) （导航栏与文章内容边距【原1200px】）
```

### 6、添加鼠标爱心特效

```js

<script>
    //鼠标点击爱心特效  放入js中即可
    !function (e, t, a) {
    function r() {
        for (var e = 0; e < s.length; e++) s[e].alpha <= 0 ? (t.body.removeChild(s[e].el), s.splice(e, 1)) : (s[e].y-- , s[e].scale += .004, s[e].alpha -= .013, s[e].el.style.cssText = "left:" + s[e].x + "px;top:" + s[e].y + "px;opacity:" + s[e].alpha + ";transform:scale(" + s[e].scale + "," + s[e].scale + ") rotate(45deg);background:" + s[e].color + ";z-index:99999");
        requestAnimationFrame(r)
    }
    function n() {
        var t = "function" == typeof e.onclick && e.onclick;
        e.onclick = function (e) {
            t && t(),
                o(e);
        };
    }
    function o(e) {
        var a = t.createElement("div");
        a.className = "heart",
            s.push({
                el: a,
                x: e.clientX - 5,
                y: e.clientY - 5,
                scale: 1,
                alpha: 1,
                color: c()
            }),
            t.body.appendChild(a);
    }
    function i(e) {
        var a = t.createElement("style");
        a.type = "text/css";
        try {
            a.appendChild(t.createTextNode(e))
        } catch (t) {
            a.styleSheet.cssText = e;
        }
        t.getElementsByTagName("head")[0].appendChild(a);
    }
    function c() {
        return "rgb(" + ~~(255 * Math.random()) + "," + ~~(255 * Math.random()) + "," + ~~(255 * Math.random()) + ")";
    }
    var s = [];
    e.requestAnimationFrame = e.requestAnimationFrame || e.webkitRequestAnimationFrame || e.mozRequestAnimationFrame || e.oRequestAnimationFrame || e.msRequestAnimationFrame ||
        function (e) {
            setTimeout(e, 1e3 / 60);
        },
        i(".heart{width: 10px;height: 10px;position: fixed;background: #f00;transform: rotate(45deg);-webkit-transform: rotate(45deg);-moz-transform: rotate(45deg);}.heart:after,.heart:before{content: '';width: inherit;height: inherit;background: inherit;border-radius: 50%;-webkit-border-radius: 50%;-moz-border-radius: 50%;position: fixed;}.heart:after{top: -5px;}.heart:before{left: -5px;}"),
        n(),
        r();
}(window, document);
</script>

```

### 7、添加鼠标烟花特效

```js
<!--鼠标点击特效-->
<script type="text/javascript" src="https://www.liuzehe.top/upload/bkjs/meme.js"></script>
<canvas class="fireworks" style="position:fixed;left:0;top:0;z-index:99999999;pointer-events:none;"></canvas>
<script type="text/javascript" src="https://www.liuzehe.top/upload/bkjs/anime.min.js"></script>
<script type="text/javascript" src="https://www.liuzehe.top/upload/bkjs/fireworks.js"></script> 
```

### 8、动态线条特效

```js
<!--动态线条特效-->
<script type="text/javascript" color="0,174,255" opacity='0.7' zIndex="-2" count="200" src="https://www.liuzehe.top/upload/bkjs/bj.js"></script>
```

