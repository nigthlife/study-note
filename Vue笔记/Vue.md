

# 目录

[TOC]



#

## 0、Vue是什么

-   Vue是一套用于构建用户界面的**渐进式框架**
-   Vue是自底向上**逐层应用**
-   Vue的核心库只关注视图层
    -   便于与第三方库或既有项目整合
    -   **允许采用简洁的模板语法来声明式地将数据渲染进 DOM 的系统**



#### CommonJS 模块化开发

CommonJS的导出导入

![image-20210407213713644](G:\各科笔记\Vue笔记\Vue.assets\image-20210407213713644.png)

![image-20210407213658222](G:\各科笔记\Vue笔记\Vue.assets\image-20210407213658222.png)

**AMD 与 CMD 规范**

>   node是最好的实现者

#### Vue生命周期图

![image-20210414090327420](G:\各科笔记\Vue笔记\Vue.assets\image-20210414090327420.png)



>    **开发环境版本**
>
>   ```html
>   <!-- 开发环境版本，包含了有帮助的命令行警告 -->
>   <script src="https://cdn.jsdelivr.net/npm/vue/dist/vue.js"></script>
>   ```
>
>   **生产环境版本**
>
>   ```html
>   <!-- 生产环境版本，优化了尺寸和速度 -->
>   <script src="https://cdn.jsdelivr.net/npm/vue"></script>
>   ```
>
>   

![image-20210328141712990](G:\各科笔记\Vue笔记\Vue.assets\image-20210328141712990.png)

## 1、[指令](#目录)

>**v- 表示它们是Vue提供的特殊attribute**	它们会在渲染dom上应用特殊的响应式行为
>
>
>
>**v-for 指令可以绑定数组的数据来渲染一个项目列表**
>
>**v-on 指令添加一个事件监听器** **简写（v-on:click=‘’ => @click=‘’）**
>
>​	通过配置具体的事件名，来绑定vue中定义的函数 具体事件名如：click点击事件 input输入事件
>
>​	**补充：**
>
>​			在响应函数里，可以指明使用event内置的参数对象，该对象表示当前对象
>
>​			可以通过event.target.value来获取当前事件对象value的值
>
>**v-model 指令它能轻松实现表单输入和应用状态之间的双向绑定**
>
>​	是将标签的value值与vue实例中的data属性值进行绑定
>
>
>
>**v-bind** **简写（<a v-bind:href='link'> => <a :href='link'>）**
>
>​	由于差值表达式不能写在HTML的标签的属性中，那么如果一定要用vue中的属性作为HTML标签的属性
>
>​	的内容，就可以通过v-bind进行属性绑定
>
>
>
>**v-once**
>
>​	表示该标签中的差值表达式只获取一次数据，之后数据的变化不影响此差值表达式的值，
>
>​	也就是获取一次数据之后就不再变化	
>
>
>
>**v-html v-text**
>
>​	v-html 会将vue中的属性的值作为html的元素来使用
>
>​	v-text 会将vue中的属性的值只作为
>
>
>
>**v-show**
>
>用于根据条件展示元素的选项是 `v-show` 指令
>
>-   用法和v-if是相同的，也就是说v-show=‘布尔值变量’ 是true的时候，就会显示内容，是false的时候就不会显示内容
>-   但是v-show改变的是元素的样式，不显示内容时样式是： display 是none 而v-if 是直接让元素消失和直接添加元素
>    -   效率上，v-show效率更高



## 2、[vue环境搭建](#目录)

**node** https://nodejs.org/en/

![image-20210409111942151](G:\各科笔记\Vue笔记\Vue.assets\image-20210409111942151.png)

安装淘宝加速器：

>   **npm install cnpm -g**
>
>   **安装vue-cli**
>
>   >   npm install --global vue-cli
>
>   >cnpm install vue-cli -g
>   >
>   >**创建脚手架死活不成功执行以下指令**
>   >
>   >npm clean cache -force

**创建webpack项目导入文件流程**

使用vue-cli创建webpack项目

>   **Vue cli2初始化项目**
>
>   vue init webpack [项目名称]
>
>   **Vue cli3初始化项目**
>
>   >   将vue-cli2升级到vue-cli3指令
>   >
>   >   npm uninstall -g vue-cli
>   >   npm install -g @vue/cli
>
>   vue create [项目名称]

![image-20210409113139874](G:\各科笔记\Vue笔记\Vue.assets\image-20210409113139874.png)

>   Project name [项目名称]
>
>   Project description [A Vue.js project]【项目描述】
>
>   Author 【作者】
>
>   Vue build 【vue构建方式】 选择第一个，运行时编译
>
>   Install vue-router 【是否安装vue-router】
>
>   Use ESLint to lint your code 【是否安装eslint】 是否对代码进行限制，代码规范，
>
>   ​	如选择了安装，会让你选择安装
>
>   ​		Standard 标准的
>
>   ​		Airbnb 别的公司的规范
>
>   ​		none 使用自己的
>
>   Set up unit tests 【是否安装单元测试】
>
>   Setup e2e tests with Noghtwatch?  【e2e => end to end 端到端测试】自动化测试
>
>   Should we run `npm install` for you after the project has been created 【是否运行安装依赖命令】
>
>   

**0、安装webpack**

**在终端里输入webpack都是全局的**

在script中定义的映射会优先找本地的

>   npm install webpack --save-dev

**1、安装router路由**

>   npm install vue-router --save-dev

**2、安装elementUI**

>npm i element-ui -Snpm i element-ui -S

**3、安装依赖**

>**方式一**
>
>npm install
>
>**方式二**
>
>npm install --registry=https://registry.npm.taobao.org

**4、安装sass加载器**

>   cnpm install sass-loader node-sass --save-dev

**5、安装axios**  艾克cos

>   npm install --save axios vue-axios

**6、启动测试**

>   npm run dev

##### **7、打包**

>   **webpack  => 前提是需要有一个webpack.config.js文件**
>
>   npm run serve
>
>   **使用  在本地安装一个webpack**
>
>   npm install webpack@3.6.0 --save-dev
>
>   **安装vue-loader vue-template加载器**
>
>   npm install vue-loader vue-template-complier --save-dev
>
>   **安装HtmlWebpackPlugin插件**
>
>   npm install html-webpack-plugin --save-dev	
>
>   **js压缩的plugin**
>
>   npm install uglifyjs-webpack-plugin@1.1.1 --save-dev
>
>   **[webpack搭建本地服务器](####搭建本地服务器)**
>
>   npm install -- save-dev webpack-dev-server@2.9.1
>
>   **安装webpack合并文件依赖**
>
>   npm install webpack-merge --save-dev
>
>   **全局安装Vue脚手架3**global
>
>   npm install -g @vue/cli



>   --save-dev 表示开发时依赖
>
>   --save 表示全局依赖



**package.json文件或者webpack.config中的配置信息**

![image-20210407221610970](G:\各科笔记\Vue笔记\Vue.assets\image-20210407221610970.png)

```js
{
    // 项目名称
  "name": "vue-admin-template",
      
  "version": "4.2.1",
  "description": "A vue admin template with Element UI & axios & iconfont & permission control & lint",
  "author": "Pan <panfree23@gmail.com>",
  // 如果是开源的需要写这个
   "license": "MIT",
      // 这是script映射指令
  "scripts": {
    "dev": "vue-cli-service serve",
    "build:prod": "vue-cli-service build",
    "build:stage": "vue-cli-service build --mode staging",
    "preview": "node build/index.js --preview",
    "lint": "eslint --ext .js,.vue src",
    "test:unit": "jest --clearCache && vue-cli-service test:unit",
    "test:ci": "npm run lint && npm run test:unit",
    "svgo": "svgo -f src/icons/svg --config=src/icons/svgo.yml"
  },
      // 运行时依赖
  "dependencies": {
    "axios": "^0.18.1",
    "element-ui": "2.12.0",
    "js-cookie": "2.2.0",
    "js-md5": "^0.7.3",
    "normalize.css": "7.0.0",
    "nprogress": "0.2.0",
    "path-to-regexp": "2.4.0",
    "vcolorpicker": "^0.1.8",
    "vue": "2.6.10",
    "vue-axios": "^3.2.4",
    "vue-router": "3.0.6",
    "vuex": "3.1.0"
  },
      // 开发时依赖
  "devDependencies": {
    "@babel/core": "7.0.0",
    "@babel/register": "7.0.0",
    "@vue/cli-plugin-babel": "3.6.0",
    "@vue/cli-plugin-eslint": "^3.9.1",
    "@vue/cli-plugin-unit-jest": "3.6.3",
    "@vue/cli-service": "3.6.0",
    "@vue/test-utils": "1.0.0-beta.29",
    "autoprefixer": "^9.5.1",
    "babel-core": "7.0.0-bridge.0",
    "babel-eslint": "10.0.1",
    "babel-jest": "23.6.0",
    "chalk": "2.4.2",
    "connect": "3.6.6",
    "eslint": "5.15.3",
    "eslint-plugin-vue": "5.2.2",
    "html-webpack-plugin": "3.2.0",
    "mockjs": "1.0.1-beta3",
    "node-sass": "^4.9.0",
    "runjs": "^4.3.2",
    "sass-loader": "^7.1.0",
    "script-ext-html-webpack-plugin": "2.1.3",
    "script-loader": "0.7.2",
    "serve-static": "^1.13.2",
    "svg-sprite-loader": "4.1.3",
    "svgo": "1.2.2",
    "vue-template-compiler": "2.6.10"
  },
  "engines": {
    "node": ">=8.9",
    "npm": ">= 3.0.0"
  },
  "browserslist": [
    "> 1%",
    "last 2 versions"
  ]
}

```



```js
'use strict'
// 引用node中的path
const path = require('path')
const defaultSettings = require('./src/settings.js')

function resolve(dir) {
  return path.join(__dirname, dir)
}

const name = defaultSettings.title || 'vue Admin Template' // page title

// If your port is set to 80,
// use administrator privileges to execute the command line.
// For example, Mac: sudo npm run
// You can change the port by the following methods:
// port = 9528 npm run dev OR npm run dev --port = 9528
const port = process.env.port || process.env.npm_config_port || 9528 // dev port

// All configuration item explanations can be find in https://cli.vuejs.org/config/
module.exports = {
  // 设置所有url的路径都会默认太前面添加一个 /XXX 或者 XXX
  publicPath: '/',
  outputDir: 'dist',
  assetsDir: 'static',
  lintOnSave: process.env.NODE_ENV === 'development',
  productionSourceMap: false,
  devServer: {
    port: port,
    open: true,
    overlay: {
      warnings: false,
      errors: true
    },
    // 代理所有以 /admin开头的网络请求
    proxy: {
      // detail: https://cli.vuejs.org/config/#devserver-proxy
      '/admin': {
        target: `http://localhost:8886/`, // 后台服务地址
        changeOrigin: true,
        pathRewrite: {
        }
      }
    }
  },
  configureWebpack: {
    // provide the app's title in webpack's name field, so that
    // it can be accessed in index.html to inject the correct title.
    name: name,
    resolve: {
      alias: {
        '@': resolve('src')
      }
    }
  },
  chainWebpack(config) {
    config.plugins.delete('preload') // TODO: need test
    config.plugins.delete('prefetch') // TODO: need test

    // set svg-sprite-loader
    config.module
      .rule('svg')
      .exclude.add(resolve('src/icons'))
      .end()
    config.module
      .rule('icons')
      .test(/\.svg$/)
      .include.add(resolve('src/icons'))
      .end()
      .use('svg-sprite-loader')
      .loader('svg-sprite-loader')
      .options({
        symbolId: 'icon-[name]'
      })
      .end()

    // set preserveWhitespace
    config.module
      .rule('vue')
      .use('vue-loader')
      .loader('vue-loader')
      .tap(options => {
        options.compilerOptions.preserveWhitespace = true
        return options
      })
      .end()

    config
    // https://webpack.js.org/configuration/devtool/#development
      .when(process.env.NODE_ENV === 'development',
        config => config.devtool('cheap-source-map')
      )

    config
      .when(process.env.NODE_ENV !== 'development',
        config => {
          config
            .plugin('ScriptExtHtmlWebpackPlugin')
            .after('html')
            .use('script-ext-html-webpack-plugin', [{
            // `runtime` must same as runtimeChunk name. default is `runtime`
              inline: /runtime\..*\.js$/
            }])
            .end()
          config
            .optimization.splitChunks({
              chunks: 'all',
              cacheGroups: {
                libs: {
                  name: 'chunk-libs',
                  test: /[\\/]node_modules[\\/]/,
                  priority: 10,
                  chunks: 'initial' // only package third parties that are initially dependent
                },
                elementUI: {
                  name: 'chunk-elementUI', // split elementUI into a single package
                  priority: 20, // the weight needs to be larger than libs and app or it will be packaged into libs or app
                  test: /[\\/]node_modules[\\/]_?element-ui(.*)/ // in order to adapt to cnpm
                },
                commons: {
                  name: 'chunk-commons',
                  test: resolve('src/components'), // can customize your rules
                  minChunks: 3, //  minimum common number
                  priority: 5,
                  reuseExistingChunk: true
                }
              }
            })
          config.optimization.runtimeChunk('single')
        }
      )
  }
}

```

![image-20210407221536121](G:\各科笔记\Vue笔记\Vue.assets\image-20210407221536121.png)

## 3、[概念](#目录)

### 1、什么是loader

>   -   loader是webpack中一个非常核心的概念
>
>   -   webpack用来做什么
>     
>       -   主要是用webpack来处理我们写的js代码，并且webpack会自动处理js之间的相关的依赖
>       -   在开发中不仅仅有基本的js代码处理，我们也需要加载css、图片、也包括一些高级的将ES6转成ES5代码，将TypeScript转成ES5代码，将scss、less转成css，将.jsx、.vue文件转成js文件
>       -   对于webpack本身的能力对于这些转化是不支持
>       
>   -   loader使用过程：
>
>       -   通过npm安装需要使用loader
>       -   在webpack.config.js中的modules关键字下进行配置
>
>   -   导入依赖.css文件
>
>       -   ```
>           require('./css/normal.css');
>           ```
>
>       -   因为只导入.css文件那么webpack会自动将.css文件打包在dist中的builds.js中，但是打包好的文件浏览器并不会识别
>
>   -   所以需要安装style-loader
>
>       -   ```
>           npm install --save-dev style-loader
>           ```
>
>       -   **注意：style-loader需要放在css-loader的前面**
>
>           -   因为webpack在读取使用的loader的过程中，是按照从右向左的顺序读取的







7、**cdn** **（内容分发网络）**



-   这是一种加速策略，能够从离自己最近的服务器上快速获取外部的资源



**8、MVVM**

>   在MVVM架构中，是不允许数据和视图直接通信，只能通过ViewModel来通信，
>
>   **而ViewModel就是定义了一个Observe观察者**
>
>   ​	ViewModel能够观察到数据的变化，并对视图对应的内容进行更新
>
>   ​	ViewModel能够监听到视图的变化，并能够通知数据发送变化
>
>   至此**Vue.js就是一个MVVM模式的实现者，他的核心就是实现了DOM监听与数据绑定**
>
>   ==MVVC通过VM实现了双向数据绑定==



**9、差值表达式**

>   **差值表达式不能作为标签中的属性值，只能作用于html中**
>
>   差值表达式调属性
>
>   {{name:‘xiao’，age:20}.name}
>
>   差值表达式调方法
>
>   {{方法名（）}}
>
>   ```html
>   <div id="app">
>   	{{[0,1,2,3,4][1]}}<br>
>           {{{name:'xiaoming',age:20}}}
>   </div>
>   ```
>
>   
>
>   **主要用于获取vue对象中的属性和方法  也就是new Vue中定义的 data 和methods**





## 4、[运用](#目录)



### 1、Vue中的事件



#### **鼠标事件： v-on:mousemove=‘’**

>   可以通过event内置函数来获取鼠标的 x y的坐标 event.clientX  event.clientY

-   **获取X Y轴坐标**
    -   **event.clientX  event.clinetY**
-   **停止鼠标移动事件**
    -   **event.stopPropagation();**
    -   另一种方式实现（**事件修饰符**）
        -   **<span @mousemove.stop>停止鼠标移动事件</spon>**

```js
// 比如一个div1里面套了一个div2 然后两个div各有一个click事件，当点击div2的事件时默认也会
// 触发div1的点击事件，所以需要在div2上设置click.stop 这样div2的事件就不会触发div1的事件
<!-- 阻止单击事件继续传播 -->
<a v-on:click.stop="doThis"></a>


<!-- 提交事件不再重载页面 -->
<form v-on:submit.prevent="onSubmit"></form>

<!-- 修饰符可以串联 -->
<a v-on:click.stop.prevent="doThat"></a>

<!-- 只有修饰符 -->
<form v-on:submit.prevent></form>

<!-- 添加事件监听器时使用事件捕获模式 -->
<!-- 即内部元素触发的事件先在此处理，然后才交由内部元素进行处理 -->
<div v-on:click.capture="doThis">...</div>

<!-- 只当在 event.target 是当前元素自身时触发处理函数 -->
<!-- 即事件不是从内部元素触发的 -->
<div v-on:click.self="doThat">...</div>

// 按键修饰符
<!-- 只有在 `key` 是 `Enter` 时调用 `vm.submit()` -->
    // keyup: 当前键盘的键弹起 只写一个keyup表示任何键都可以调用
    // keyup.enter: 表示按下回车键执行submit
    // keyup.space: 按下空格之后执行
<input v-on:keyup.enter="submit">
```



### 2、[计算属性（computed）](#目录)

**什么是计算属性**

>   一些常用函数可以缓存起来，在调用时直接使用缓存中的过程（结果）依此来提高效率
>
>   computed里虽然存放的是函数，但在调用时，computed里的东西是一个属性
>
>   **所以我们在调用时不能使用小括号（），因为（）是在调用函数，而不是在调用属性**

-   计算属性的重点突出在==属性==两个字上，首先它是一个属性，其次这个属性有计算能力
    -   这里的计算就是个函数，简单点说，**它就是一个能够将计算结果缓存起来的==属性==**
    -   **将行为转化成了静态的属性**



>   计算属性默认拥有get与set方法
>
>   ```js
>   component： {
>   	属性名: {
>   		get: function(){
>   		
>   		},
>               // 写了set方式后，在浏览器中就可以直接使用对象的名称访问到这个属性进行设置
>   		set: function(newVlaue){
>   		
>   		}
>   		// 因为计算属性一般是没有set方法的，它是只读属性
>           	// 所以我们一般这么写
>           	属性名：{
>               	   get: {
>                          	 get方式体
>                          }
>                   }
>           	// 然后再进行简化
>           	属性名：{
>                   	get方式体
>                  }
>   	}
>   }
>   ```
>
>   



### 3、[watch （监控属性）](#目录)

>   通过watch里给属性绑定函数，当属性的值发生变化时，该函数就会自动被调用，调用时可以接收两参数
>
>   （newValue,oldValue）第一个参数为属性改变后的值，第二参数是属性改变前的值

```js
<div id="app">
    {{title}}
    <input type="text" v-model="title">
</div>
<body>
    <srcipt>
        var v1 = new Vue({
            el: "#app",
            data: {
            title: "hello vue"	
        },
        // 监听  监听title如果它发生改变将调用一个函数，函数有俩个参数新的值和旧的值
        watch: {
            title: function(newValue,oldValue){
        
            	console.log(newValue + ":" + oldValue)
            	}
       		}
        })
    </srcipt>
</body>
```







### 4、[vue 改变样式](#目录)

>   绑定样式可分为两种
>
>   **class 为内部引入**
>
>   **style 为内嵌引入**
>
>   ![image-20210406132956789](G:\各科笔记\Vue笔记\Vue.assets\image-20210406132956789.png)

let temp = true 

temp =！temp  表示取反赋值

![image-20210406122841683](G:\各科笔记\Vue笔记\Vue.assets\image-20210406122841683.png)

![image-20210406122952180](G:\各科笔记\Vue笔记\Vue.assets\image-20210406122952180.png)



**另一种方式：**

使用一个计算属性返回一个样式的true/false是否使用

![image-20210406123356814](G:\各科笔记\Vue笔记\Vue.assets\image-20210406123356814.png)

#### [改变多个样式](#目录)

使用数组的方式添加多个样式

```html
<div :class="[mycolor,mw]" class="mydiv"></div>

new Vue({
	el: "#app",
	data: {
		temp: false,
		mw: "mywidth",
		mycolor: "green"
	}
})
```



### 5、[分支语句](#目录)

![image-20210406135329127](G:\各科笔记\Vue笔记\Vue.assets\image-20210406135329127.png)



#### v-show

-   用法和v-if是相同的，也就是说v-show=‘布尔值变量’ 是true的时候，就会显示内容，是false的时候就不会显示内容
-   但是v-show改变的是元素的样式，不显示内容时样式是： display 是none 而v-if 是直接让元素消失和直接添加元素
    -   效率上，v-show效率更高

#### template

-   在vue中会经常遇到，目前可以使用该标签配合v-if实现多个元素一起出现，一起消失，
-   但是它不能和v-show一起用



### 6、[Vue对象的操作](#目录)

可以通过一个Vue对象操作另一个Vue对象

Vue对象操作另一个Vue对象的内容，维度有两个，操作属性、操作方法



### 7、[Vue的实例属性](#目录)

-   直接通过对象的方式调用的属性，是来自与data或computed中的属性
-   但是vue对象中的el、data这些键也称为属性，这些属性就是vue**对象的实例属性**
    -   **v1.$data   这就是调用某个vue对象中的data实例属性**
    -   也可以 **v1.$data.title  相当于 v1.title**

>   -   **ref的使用**
>       -   在vue里面，往往使用ref属性来代替id属性的使用，那么可以快速的通过ref的值来获取页面中的某个元素
>       -   this.$refs.ref名称 
>       -   ![image-20210406163549324](G:\各科笔记\Vue笔记\Vue.assets\image-20210406163549324.png)、
>   -   **mount的使用**
>       -   实现了页面的元素和vue对象的动态绑定，之前都是通过el的方式来绑定，也可以通过mount实例属性进行绑定
>       -   ![image-20210406163948579](G:\各科笔记\Vue笔记\Vue.assets\image-20210406163948579.png)



### 8、[vue的组件](#目录)

-   要想实现组件化，需要在页面中注册组件，关于注册额组件方式有两种，分别是全局注册是本地注册
-   vue的全局注册也就是意味着在页面的任意一个被vue绑定的div中，都可以使用全局注册了的vue组件
    -   **但是，如果是对vue组件进行本地注册，那么在其他被vue绑定的div中，不能使用该组件**

**组件模板分离写法**

![image-20210407151345541](G:\各科笔记\Vue笔记\Vue.assets\image-20210407151345541.png)

![image-20210407151354279](G:\各科笔记\Vue笔记\Vue.assets\image-20210407151354279.png)

![image-20210407151520781](G:\各科笔记\Vue笔记\Vue.assets\image-20210407151520781.png)

**局部注册**

**![image-20210406205215858](G:\各科笔记\Vue笔记\Vue.assets\image-20210406205215858.png)**



**使用组件**

-   在被vue绑定了的html元素中才能使用组件，如果一个div没有被vue绑定，那么这个div中不能使用之前注册的组件

**特点**

-   template是将内容战现在页面上的一个键，值是一个字符串，
-   template里边必须有且只能有一个根元素



### 9、[vue的生命周期](#目录)



```js
生命周期钩子函数
// 在被创建之前调用此函数
beforCreate(){} 
beforCreate:function(){}



```

>   **一个vue对象会经历 初始化、创建、绑定、更新、销毁等阶段，不同的阶段都会有相应的生命周期钩子函数被调用**
>
>   
>
>   首先实例化一个vue对象，然后进行init初始化事件，然后如果有beforCreate函数，那么**创建实例之前执行beforeCreatae钩子事件**然后进行初始化注入，**创建完实例后可执行created钩子**，然后判断有木有el选项，然后在**绑定el选项之前调用**
>
>   **beforMount钩子事件**，el绑定**完成之后执行mounted函数**，这个函数在整个实例中**只执行一次**
>
>   之后如果**发生更新操作会先调用beforeUpdate钩子**，**更新完成之后再调用updated钩子**
>
>   最后实例**销毁之前会执行beforeDestroy钩子**，正式**被销毁调用destroyed钩子**



### 10、[组件参数传递](#目录)



![image-20210406220658866](G:\各科笔记\Vue笔记\Vue.assets\image-20210406220658866.png)

-   通过子组件的props部分来指明可以接收的参数，父组件通过在标签中写明参数的键值对来传递参数

**写法**

![image-20210406220911272](G:\各科笔记\Vue笔记\Vue.assets\image-20210406220911272.png)



### 11、以事件发射的方式来实现子传父的效果

-   在子组件中，使用 this.$emit(“键”,“值”)
-   在父组件中，子组件的标签中使用 @键=“变量名=$event” 
    -   其中$event就能得到值，变量名为父组件中的vue属性





### 12、[axios](#目录)

-   Axios是一个开源的可以用在浏览器端和NodeJs的异步通信框架，他的主要作用就是实现ajax异步通信
-   功能：
    -   从浏览器中创建XMLHttpRequests
    -   从node.js创建http请求
    -   支持Promise API
    -   拦截请求和响应
    -   转换请求数据和响应数据
    -   取消请求
    -   自动转换JSON数据
    -   客户端支持防御XSRF (跨站请求伪造)



### 13、[跨域问题](#目录)

>   **跨域，指的是浏览器不能执行其他网站的脚本，它是由浏览器的同源策略造成的，是浏览器对**
>
>   **JavaScript施加的安全限制**
>
>   **什么是同源策略**
>
>   ​	**同源指的是：域名、协议、端口均相同**
>
>   ​	![image-20210407091900299](G:\各科笔记\Vue笔记\Vue.assets\image-20210407091900299.png)

#### 解决跨域问题

>   -   SpringMVC配置cors
>   -   拦截器的方式配置解决跨域
>   -   SpringBoot配置cors
>
>   
>
>   **使用CORS (跨资源共享) **
>
>   cors是一个W3C的标准，全称跨域资源共享，他允许浏览器向跨源服务器发出XMLHttpResuqt请求
>
>   从而客服了ajax只能同源使用的限制
>
>   cors需要浏览器和服务器同时支持，目前所有浏览器都支持
>
>   服务器只要实现了cors接口，就可以跨源通信（在header中设置  Access-Control-Allow-Origin）
>
>   **CORS与JSONP的比较**
>
>   -   JSONP只支持get请求，cors支持所有类型的http请求
>   -   JSONP的优势在于支持老式浏览器，以及可以向不支持cors的网站请求数据
>
>   **![image-20210407092814861](G:\各科笔记\Vue笔记\Vue.assets\image-20210407092814861.png)**



### 14、[路由](#目录)

第一种方式

>   <button type="button" @click=‘btnfn>点我</button>
>
>   btnfn() {
>
>   ​	this.$router.push(“路由地址”)
>
>   }

 ![image-20210407103921969](G:\各科笔记\Vue笔记\Vue.assets\image-20210407103921969.png)

第二种方式

>   通过HTML中的路由<router-link to='路由地址' />



### 15、Vue中组件样式表的作用范围

-   如果vue组件中的style标签没有带上scoped属性，那么这个style的样式将会作用在整个页面中
-   那么加上scoped，让样式只作用在当前组件中

![image-20210407104415409](G:\各科笔记\Vue笔记\Vue.assets\image-20210407104415409.png)







### 16、[模块化开发](#目录)

#### Es6的模块化导入导出

![image-20210407175432012](G:\各科笔记\Vue笔记\Vue.assets\image-20210407175432012.png)



![image-20210407175046762](G:\各科笔记\Vue笔记\Vue.assets\image-20210407175046762.png)

![image-20210407175527701](G:\各科笔记\Vue笔记\Vue.assets\image-20210407175527701.png)



#### export default

>   某些情况下，一个模块中包含某个功能，我们并不希望给这个功能命名，而且让
>
>   导入者可以自己来命名，这个时候就可以使用export default
>
>   **注意：export default在同一个模块中，不允许同时存在多个**

#### [导入多个模块](#目录)

使用通配符然后再取一个别名

![image-20210407180517982](G:\各科笔记\Vue笔记\Vue.assets\image-20210407180517982.png)







## 5、[Vue的核心 虚拟DOM 和 diff算法](#目录)

>   vue 的高效的核心就是虚拟DOM，普通的js操作Dom是直接操作DOM树，而不是直接操作页面上的DOM，普通的js需要将
>
>   页面上的DOM转换为DOM树，然后根据其选中的 节点去进行更改，然后在把更改后的DOM树重新返回给页面，这就效率就低
>
>   而vue不通过修改DOM树，而是直接操作页面上的DOM对象，然后通过diff算法去计算虚拟DOM和原来的DOM的区别，然后在原来的DOM基础上对
>
>   虚拟DOM进行修改，从而提高效率，diff也就是different区别算法

![image-20210406134606613](G:\各科笔记\Vue笔记\Vue.assets\image-20210406134606613.png)

diff = different（区别）





## 6、[方法](#目录)

>   toUpperCase()  转大写
>
>   toLowerCase()  转小写
>
>   split() 	进行分割
>
>   高阶函数
>
>   filter map reduce
>
>   **Filter过滤函数**
>
>   ```
>   filter中的回调函数有一个要求：必须返回一个boolean值
>   当回调函数返回true：函数内部会自动将这次回调的参数值加入到新的数组中
>   当前回调函数返回false：函数内部会自动过滤这次的参数的值
>   ```
>
>   **map函数**
>
>   ```
>   如果想对数组中的所有值都进行某一次的变化就可以使用map函数
>   ```
>
>   **reduce函数**
>
>   >   作用：对数组中所有的内容进行汇总（加减乘除）
>   >
>   >   参数至少需要俩个值	
>
>   ![image-20210407145253042](G:\各科笔记\Vue笔记\Vue.assets\image-20210407145253042.png)
>
>   计算总数
>
>   ![image-20210407150540057](G:\各科笔记\Vue笔记\Vue.assets\image-20210407150540057.png)
>
>   ![image-20210407145446111](G:\各科笔记\Vue笔记\Vue.assets\image-20210407145446111.png)
>
>   **最终结果**
>
>   ![image-20210407145705262](G:\各科笔记\Vue笔记\Vue.assets\image-20210407145705262.png)



![image-20210407134054341](G:\各科笔记\Vue笔记\Vue.assets\image-20210407134054341.png)



## 7、[webpack](#目录)

### 1、概念(模块化打包工具)

-   从本质上讲，webpack是一个现代的JavaScript应用的静态**模块打包**工具
-   打包工具有：grunt、gulp、webpack、

![image-20210408095924892](G:\各科笔记\Vue笔记\Vue.assets\image-20210408095924892.png)



### 7.1、less文件处理

**安装开发时依赖**

```js
npm install --save-dev less-loader less
```

然后将该 loader 添加到 `webpack` 的配置中去webpack.config.js

```js
module.exports = {
  module: {
    rules: [  // rules对应一个数组，可配置多个规则
      {
        test: /\.less$/i,
        loader: [ // compiles Less to CSS
          "style-loader",
          "css-loader",
          "less-loader",
        ],
      },
    ],
  },
};
接着使用你习惯的方式运行 webpack。

可选项 
```

![image-20210408100330499](G:\各科笔记\Vue笔记\Vue.assets\image-20210408100330499.png)

![image-20210408101548690](G:\各科笔记\Vue笔记\Vue.assets\image-20210408101548690.png)



### 7.2、处理url引用类型文件（图片）

**首先，你需要安装 `url-loader`：**

```java
// 安装的是开发时依赖
npm install url-loader --save-dev
// 加载的图片大于limit的数值需要安装依赖
npm install --save-dev file-loader
    
    // index.js导入
import img from './image.png';

	// webpack.config.js配置
module.exports = {
  module: {
    rules: [
      {
        test: /\.(png|jpg|gif)$/i,
        use: [
          {
            loader: 'url-loader',
            options: {
                // 当加载的图片小于limit时，会将图片编译成base64字符串形式
                // 当图片大于这个数值时，需要使用file-loader进行加载，需要安装一个file-loader
              limit: 8192,
                // 可添加一个name,表示打包后的文件都放到img文件中
              	// ，然后名称为他原来的名称.hashcode值默认截取8位.原来的后缀扩展名
              name: 'img/[name].[hsag:8].[ext]'
            },
          },
        ],
      },
    ],
  },
};
然后通过你的首选方法运行 webpack。


```

![image-20210408111324988](G:\各科笔记\Vue笔记\Vue.assets\image-20210408111324988.png)

![image-20210408111304502](G:\各科笔记\Vue笔记\Vue.assets\image-20210408111304502.png)



### 7.3、ES6语法处理

如果希望将ES6的语法转成ES5，那么就需要使用babel

在webpack中，我们直接使用babel对应的loader

![image-20210408112330872](G:\各科笔记\Vue笔记\Vue.assets\image-20210408112330872.png)

#### **出现runtime-only需配置（不可以有任何template）**

#### webpack.config.js

```js
module.exports = {
    // 程序的入口
    entry: './src/main.js',
    // 打包的出口
    output: {
        filename: 'bundle.js',
        // 设置url文件引用路径，魔谭添加一个dist
        publicPath: 'dist/'
    }
    module:{
    	rules: [{
    		test: /\.css$/,
    		// css-loader只负责将css文件进行加载
    		// style-loader负责将样式添加DOM中
    		// 使用多个loader时，是从右向左
    		use: [
    			'style-loader','css-loader'
    		]
		},{
            test: /\.(png|jpg|gif|jpeg)$/
            use: [
                {
                    loader: 'usr-loader',
                    options: {
                        limit: 13000,
                        name: 'img/[name].[hash:8].[ext]'
                    }
                }
            ]
        },{
            // 在 webpack 配置对象中，需要将 babel-loader 添加到 module 列表中
            test: /\.js$/,
            exclude: 
            use: {
                loader: 'babel-loader',
                options: {
                    presets: ['es2015']
                }
            }
        }]
	}
    resolve: {
    	//alias： 别名
    	alias:{
    		// 指定使用的vue文件
    		// 指定这个文件可以有template ，因为有complier可以用于编译template
			'vue$': 'vue/dist/vue.esm.js'
		}
	},
    // 配置本地服务器
    devServer: {
        // 配置为哪个文件夹提供本地服务
        contenBase: './dist'，
        inline: true,  // 是否实时
        port: 端口号 （默认8080端口）,
        
    },
    plugins: {
        // 在打包文件最上添加横幅
     	new webpack.BannerPlugin("最终版权xxx所有"),
        // 指定html页面模板
        new HtmlWebpackPlugin({
            template: 'index.html'
        })，
        // 压缩代码
        new UglifyjsWebpackPlugin()
    }
}

```

### 7.4、el和template的区别

![image-20210408211010269](G:\各科笔记\Vue笔记\Vue.assets\image-20210408211010269.png)

![image-20210408211031059](G:\各科笔记\Vue笔记\Vue.assets\image-20210408211031059.png)

**SPA（simple page web application） 单页面复应用**

**需要让编译器认识.vue文件需要安装loader**这样才能对.vue文件真正的进行编译

**安装vue-loader vue-template加载器**

```
npm install vue-loader vue-template-complier --save-dev
```

![image-20210408212343713](G:\各科笔记\Vue笔记\Vue.assets\image-20210408212343713.png)

#### 解决省略后缀名问题

![image-20210408213006996](G:\各科笔记\Vue笔记\Vue.assets\image-20210408213006996.png)



### 7.4、plugin（插件）

#### 添加版权plugin

![image-20210409093755507](G:\各科笔记\Vue笔记\Vue.assets\image-20210409093755507.png)

![image-20210409094424091](G:\各科笔记\Vue笔记\Vue.assets\image-20210409094424091.png)

#### 打包html的plugin

![image-20210409095210339](G:\各科笔记\Vue笔记\Vue.assets\image-20210409095210339.png)



![image-20210409095950496](G:\各科笔记\Vue笔记\Vue.assets\image-20210409095950496.png)

#### [js压缩的plugin](###7、打包)

![image-20210409101151529](G:\各科笔记\Vue笔记\Vue.assets\image-20210409101151529.png)

![image-20210409101513181](G:\各科笔记\Vue笔记\Vue.assets\image-20210409101513181.png)



#### 搭建本地服务器

![image-20210409101727091](G:\各科笔记\Vue笔记\Vue.assets\image-20210409101727091.png)

[配置文件路径](####webpack.config.js)

![image-20210409103230184](G:\各科笔记\Vue笔记\Vue.assets\image-20210409103230184.png)

![image-20210409110055115](G:\各科笔记\Vue笔记\Vue.assets\image-20210409110055115.png)













## 8、[vue-cli](#目录)

#### 8.1、vue-cli概念

-   CLI (command line interfaces) 命令行接口
-   在进行Vue项目开发时，可以选择不同的Vue模板（骨架）进行项目的搭建
    -   如simple、webpack-simple、webpack、browserify/browserify-simple
-   vue-cli是官方提供的一个脚手架，（预先定义好的目录结构及基础代码，在创建Maven项目时可以选择创建一个骨架项目
    -   这个骨架项目就是脚手架，用于快速生成一个vue的项目模板）



#### 8.2、node.js概念

**node就是为js代码提供了运行环境，让js代码不用在依赖html和浏览器也能单独进行运行**

谷歌的**V8引擎（开源）**可以直接将js代码编译成二进制码然后直接运行

而火狐、IE需要将js代码编译成字节码 然后在给浏览器运行

-   Node.js是-一个基于Chrome V8引擎的JavaScript 运行环境。Node.js 使用了一个事件驱动、非阻塞式10的模型。
-   Node是一个让JavaScript 运行在服务端的开发平台，它让JavaScript成为与PHP、Python、 Perl、 Ruby等服务端语言平
    起平坐的脚本语言。(21 发布于2009年5月，由Ryan Dahl开发，实质是对Chrome V8引擎进行了封装。
-   Node对-些特殊用例进行优化，提供昝代的API,使得V8在非浏览器环境下运行得更好。V8引擎执行Javascript的速度非常
    快，性能非常好。Node是- -个基 于Chrome JavaScrip运行时建立的平台，用于方便地搭建响应速度快、 易于扩展的网络应用。
    Node使用事件驱动，非阻塞I/O 模型而得以轻量和高效，非常适合在分布式设备上运行数据密集型的实时应用。



#### 8.3、vue-cli目录结构解析

![image-20210409152849757](G:\各科笔记\Vue笔记\Vue.assets\image-20210409152849757.png)

**builder和config文件夹目录下的文件夹都是一些配置**

##### 2、package-lock.json解析

**里面记录的都是node-modules中安装的真实版本信息**

##### 1、package.json解析

**里面记录的都是一些大概的版本信息**

```json
{
  "name": "my_text_one",
  "version": "1.0.0",
  "description": "A Vue.js project",
  "author": "wlp",
  "private": true,
  "scripts": {
      // 开发时使用，这里会搭建一个本地服务器
      // --config build/webpack.dev.conf.js 自己指定在哪里运行这个webpack-dev-server
    "dev": "webpack-dev-server --inline --progress --config build/webpack.dev.conf.js",
    "start": "npm run dev",
      
      // 打包项目 通过一个node指令 node可以直接执行js文件  找到build.js文件然后进行打包
    "build": "node build/build.js"
  },
    // 运行时的依赖
  "dependencies": {
    "axios": "^0.21.1",
    "element-ui": "^2.15.1",
      // vue的版本
    "vue": "^2.5.2", => 脚手架cli2用的版本，cli3是用的最新版
    "vue-axios": "^3.2.4",
    "vue-router": "^3.0.1"
  },
    // 开发时的依赖
  "devDependencies": {
    "autoprefixer": "^7.1.2",
    "babel-core": "^6.22.1",
    "babel-helper-vue-jsx-merge-props": "^2.0.3",
    "babel-loader": "^7.1.1",
    "babel-plugin-syntax-jsx": "^6.18.0",
    "babel-plugin-transform-runtime": "^6.22.0",
    "babel-plugin-transform-vue-jsx": "^3.5.0",
      // 添加了-env需要单独添加一个.babelrc配置文件 babel将Es6转换为Es5
    "babel-preset-env": "^1.3.2",
    "babel-preset-stage-2": "^6.22.0",
    "chalk": "^2.0.1",
    "copy-webpack-plugin": "^4.0.1",
    "css-loader": "^0.28.0",
    "extract-text-webpack-plugin": "^3.0.0",
    "file-loader": "^1.1.4",
    "friendly-errors-webpack-plugin": "^1.6.1",
    "html-webpack-plugin": "^2.30.1",
    "node-notifier": "^5.1.2",
    "optimize-css-assets-webpack-plugin": "^3.2.0",
    "ora": "^1.2.0",
    "portfinder": "^1.0.13",
    "postcss-import": "^11.0.0",
    "postcss-loader": "^2.0.8",
    "postcss-url": "^7.2.1",
    "rimraf": "^2.6.0",
    "semver": "^5.3.0",
    "shelljs": "^0.7.6",
    "uglifyjs-webpack-plugin": "^1.1.1",
    "url-loader": "^0.5.8",
    "vue-loader": "^13.3.0",
    "vue-style-loader": "^3.0.1",
    "vue-template-compiler": "^2.5.2",
    "webpack": "^3.6.0",
    "webpack-bundle-analyzer": "^2.9.0",
    "webpack-dev-server": "^2.9.1",
    "webpack-merge": "^4.1.0"
  },
  "engines": {
    "node": ">= 6.0.0",
    "npm": ">= 3.0.0"
  },
  "browserslist": [
    "> 1%",
    "last 2 versions",
    "not ie <= 8"
  ]
}

```

```js
{
  "presets": [
    ["env", {
      "modules": false,
      "targets": {
          // 需要适配的浏览器，市场份额大于1%的浏览器并且最后的2个版本需要 ie版本小于8就不考虑
        "browsers": ["> 1%", "last 2 versions", "not ie <= 8"]
      }
    }],
      // stage 阶段 babel-preset-stage-2
    "stage-2"
  ],
      // 依赖的插件
  "plugins": ["transform-vue-jsx", "transform-runtime"]
}

```



##### 2、build.js

```js
'use strict'
require('./check-versions')()

process.env.NODE_ENV = 'production'

const ora = require('ora')
const rm = require('rimraf')
const path = require('path')
const chalk = require('chalk')
const webpack = require('webpack')
const config = require('../config')
const webpackConfig = require('./webpack.prod.conf')

const spinner = ora('building for production...')
spinner.start()

// rm => remove  在你第二次执行npm run build 的时候会把之前那次打包好的dist文件夹给删除
rm(path.join(config.build.assetsRoot, config.build.assetsSubDirectory), err => {
  // 判断删除过程中是否有异常，如果有直接抛出
    if (err) throw err
    // 这里直接执行webpack的相关配置  webpackConfig 这个是在文件在上面require导入
  webpack(webpackConfig, (err, stats) => {
    spinner.stop()
    if (err) throw err
    process.stdout.write(stats.toString({
      colors: true,
      modules: false,
      children: false, // If you are using ts-loader, setting this to true will make TypeScript errors show up during build.
      chunks: false,
      chunkModules: false
    }) + '\n\n')

    if (stats.hasErrors()) {
      console.log(chalk.red('  Build failed with errors.\n'))
      process.exit(1)
    }

    console.log(chalk.cyan('  Build complete.\n'))
    console.log(chalk.yellow(
      '  Tip: built files are meant to be served over an HTTP server.\n' +
      '  Opening index.html over file:// won\'t work.\n'
    ))
  })
})

```

##### 8.3、webpack.prod.conf

```js
'use strict'
const path = require('path')
const utils = require('./utils')
const webpack = require('webpack')
const config = require('../config')
const merge = require('webpack-merge')
// 这里导入基础配置文件
const baseWebpackConfig = require('./webpack.base.conf')

const CopyWebpackPlugin = require('copy-webpack-plugin')
const HtmlWebpackPlugin = require('html-webpack-plugin')
const ExtractTextPlugin = require('extract-text-webpack-plugin')
const OptimizeCSSPlugin = require('optimize-css-assets-webpack-plugin')
const UglifyJsPlugin = require('uglifyjs-webpack-plugin')

const env = require('../config/prod.env')

// 合并基础配置
const webpackConfig = merge(baseWebpackConfig, {
  module: {
    rules: utils.styleLoaders({
      sourceMap: config.build.productionSourceMap,
      extract: true,
      usePostCSS: true
    })
  },
```

##### 8.5、webpack.dev.config.js

```js
'use strict'
const utils = require('./utils')
const webpack = require('webpack')
const config = require('../config')
const merge = require('webpack-merge')
const path = require('path')
const baseWebpackConfig = require('./webpack.base.conf')
const CopyWebpackPlugin = require('copy-webpack-plugin')
const HtmlWebpackPlugin = require('html-webpack-plugin')
const FriendlyErrorsPlugin = require('friendly-errors-webpack-plugin')
const portfinder = require('portfinder')

const HOST = process.env.HOST
const PORT = process.env.PORT && Number(process.env.PORT)

// 合并公共的配置文件
const devWebpackConfig = merge(baseWebpackConfig, {
  module: {
    rules: utils.styleLoaders({ sourceMap: config.dev.cssSourceMap, usePostCSS: true })
  },
  // cheap-module-eval-source-map is faster for development
  devtool: config.dev.devtool,

  // these devServer options should be customized in /config/index.js
  devServer: {
    clientLogLevel: 'warning',
    historyApiFallback: {
      rewrites: [
        { from: /.*/, to: path.posix.join(config.dev.assetsPublicPath, 'index.html') },
      ],
    },
    hot: true,
    contentBase: false, // since we use CopyWebpackPlugin.
    compress: true,
    host: HOST || config.dev.host,
    port: PORT || config.dev.port,
    open: config.dev.autoOpenBrowser,
    overlay: config.dev.errorOverlay
      ? { warnings: false, errors: true }
      : false,
    publicPath: config.dev.assetsPublicPath,
    proxy: config.dev.proxyTable,
    quiet: true, // necessary for FriendlyErrorsPlugin
    watchOptions: {
      poll: config.dev.poll,
    }
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env': require('../config/dev.env')
    }),
    new webpack.HotModuleReplacementPlugin(),
    new webpack.NamedModulesPlugin(), // HMR shows correct file names in console on update.
    new webpack.NoEmitOnErrorsPlugin(),
    // https://github.com/ampedandwired/html-webpack-plugin
    new HtmlWebpackPlugin({
      filename: 'index.html',
      template: 'index.html',
      inject: true
    }),
    // copy custom static assets
    new CopyWebpackPlugin([
      {
        from: path.resolve(__dirname, '../static'),
        to: config.dev.assetsSubDirectory,
        ignore: ['.*']
      }
    ])
  ]
})

module.exports = new Promise((resolve, reject) => {
  portfinder.basePort = process.env.PORT || config.dev.port
  portfinder.getPort((err, port) => {
    if (err) {
      reject(err)
    } else {
      // publish the new Port, necessary for e2e tests
      process.env.PORT = port
      // add port to devServer config
      devWebpackConfig.devServer.port = port

      // Add FriendlyErrorsPlugin
      devWebpackConfig.plugins.push(new FriendlyErrorsPlugin({
        compilationSuccessInfo: {
          messages: [`Your application is running here: http://${devWebpackConfig.devServer.host}:${port}`],
        },
        onErrors: config.dev.notifyOnErrors
        ? utils.createNotifierCallback()
        : undefined
      }))

      resolve(devWebpackConfig)
    }
  })
})

```

##### 8.6、config文件夹下的index.js这里全都是配置好的一些变量

**dev.env.js为开发时的一些变量**

**prod.env.js为运行时的一些变量**

**这些变量会在build文件中的配置中会用到**

```js
'use strict'
// Template version: 1.3.1
// see http://vuejs-templates.github.io/webpack for documentation.

const path = require('path')

module.exports = {
  dev: {

    // Paths
    assetsSubDirectory: 'static',
    assetsPublicPath: '/',
    proxyTable: {},

    // Various Dev Server settings
      // 主机名
    host: 'localhost', // can be overwritten by process.env.HOST
      // 端口号
    port: 8080, // can be overwritten by process.env.PORT, if port is in use, a free one will be determined
      // 是否自动打开浏览器
    autoOpenBrowser: false,
    errorOverlay: true,
    notifyOnErrors: true,
    poll: false, // https://webpack.js.org/configuration/dev-server/#devserver-watchoptions-

    
    /**
     * Source Maps
     */

    // https://webpack.js.org/configuration/devtool/#development
    devtool: 'cheap-module-eval-source-map',

    // If you have problems debugging vue-files in devtools,
    // set this to false - it *may* help
    // https://vue-loader.vuejs.org/en/options.html#cachebusting
    cacheBusting: true,

    cssSourceMap: true
  },

  build: {
    // Template for index.html
    index: path.resolve(__dirname, '../dist/index.html'),

    // Paths
    assetsRoot: path.resolve(__dirname, '../dist'),
    assetsSubDirectory: 'static',
    assetsPublicPath: '/',

    /**
     * Source Maps
     */

    productionSourceMap: true,
    // https://webpack.js.org/configuration/devtool/#production
    devtool: '#source-map',

    // Gzip off by default as many popular static hosts such as
    // Surge or Netlify already gzip all static assets for you.
    // Before setting to `true`, make sure to:
    // npm install --save-dev compression-webpack-plugin
    productionGzip: false,
    productionGzipExtensions: ['js', 'css'],

    // Run the build command with an extra argument to
    // View the bundle analyzer report after build finishes:
    // `npm run build --report`
    // Set to `true` or `false` to always turn it on or off
    bundleAnalyzerReport: process.env.npm_config_report
  }
}

```

##### 8.7、static文件夹

**可将一些静态文件放置在这个文件夹中，然后项目在打包时会默认把这个文件夹中的东西**

**原封不动的复制到dist文件夹中**不会走limit判断

**其中的gitkeep文件的用处是不管这个文件夹是否为不为空都放置在dist文件中去**

**如果是放在src下那么会根据limit去判断是否直接放过去还是编译成base64**

##### 8.8、.editorconfig文件

##### .gitignore文件配置的是上传需要忽略的文件

```properties
# 当root=true时对下面的文件进行解析
root = true
# 对代码的风格进行统一
[*]
# 使用的编码格式
charset = utf-8
# 缩进的风格 为 空格
indent_style = space
# 缩进的大小为2个空格
indent_size = 2
# 在最后一行换行 根据lf进行换行
end_of_line = lf
# 在最后一行代码加一个换行
insert_final_newline = true
# 删除一些无用的空格
trim_trailing_whitespace = true

```

![image-20210409222853264](G:\各科笔记\Vue笔记\Vue.assets\image-20210409222853264.png)

ast（抽象语法树  abstract syntax tree）



##### **8.8、runtime+complier 与 runtimeonly的区别**

-   runtime+complier 在导入APP的时候会在components中注册，然后在放在template中去

-   runtimeonly会有一个render函数，然后就可以使用render函数直接将这个app组件转成虚拟dom，然后直接到UI

    >   ```js
    >   // 这个h为什么叫h，因为这个里面传入的是一个回调函数，这个函数叫createElement（创建元素）
    >   // 他里面有三个参数 第一个参数为标签 第二个参数为 {标签的属性}  第三个参数为 [内容]
    >   render： funaction（h）{
    >   }
    >   ```
    >
    >   



>   我们写的html都户写在template中，然后内部会进行解析，解析成一个抽象语法树（ast），然后编译成对应的render函数
>
>   然后再形成一个虚拟dom，然后最后再转成一个真实dom

![image-20210409225914387](G:\各科笔记\Vue笔记\Vue.assets\image-20210409225914387.png)

![image-20210409225934545](G:\各科笔记\Vue笔记\Vue.assets\image-20210409225934545.png)





## 9、vue-cli3

![image-20210409230413208](G:\各科笔记\Vue笔记\Vue.assets\image-20210409230413208.png)

#### 9.1、创建cli3项目

```js
? Please pick a preset: (Use arrow keys)
> Default ([Vue 2] babel, eslint)  => 默认的vue2 的项目
  Default (Vue 3 Preview) ([Vue 3] babel, eslint) => 默认的vue3的项目
  Manually select features	=> 手动的选择特性（选择这个）

>(*) Choose Vue version
 (*) Babel => 将es6转换成es5的一个转换器
 ( ) TypeScript => 
 ( ) Progressive Web App (PWA) Support => 先进的web app
 ( ) Router => 路由
 ( ) Vuex => 状态管理模式
 ( ) CSS Pre-processors => css加载器
 (*) Linter / Formatter	=> 代码规范
 ( ) Unit Testing => 测试单元
 ( ) E2E Testing  => 端到端测试

> ESLint with error prevention only => 只有错误预防的ESLint
  ESLint + Airbnb config => Airbnb的代码规范
  ESLint + Standard config => 标准的代码规范
  ESLint + Prettier =>漂亮的
>(*) Lint on save => 保存时的提示
 ( ) Lint and fix on commit => 检测和修复的提交

// 你喜欢把配置文件放置哪里
? Where do you prefer placing config for Babel, ESLint, etc.? (Use arrow keys)
> In dedicated config files => 专门的配置文件中，需自己写
  In package.json => package.json 中
// 是否把之前的配置将其保存为将来项目的预设值
  ? Save this as a preset for future projects? (y/N)
  	Save preset as:  => 输入需要保存的名称
```

**git指令**

>   git init 生成一个本地仓库
>
>   git add .   进行一次提交
>
>   git push  推送到远程仓库中
>
>   git commit -m  ‘备注信息’
>
>   git static  查看git的状态

##### 9.2、查看vue-cli3的配置文件

>   1.  通过命令
>
>       vue ui 进入图形化界面
>
>   2.  需要修改或添加自己的独有的配置需要在最外层目录添加一个vue.config.js文件
>
>   3.  然后就可以在其中添加自己的配置文件





## 10、vue-router

### 10.1、什么是路由

-   路由就是决定数据包从来源到目的地的路径
-   转送将输入端的数据转移到合适的输出端
-   **路由中有一个非常重要的概念叫路由表**
    -   路由表本质上就是一个映射表，决定了数据包的指向
-   **前端路由**
    -   首先因为我们使用vue创建的项目只有一个html，因为只有一个htm所以也被称为
    -   单页富应用（SPA） => 一个页面有很多的功能的应用，然后由于vue打包发布项目的时候会把所有的
    -   html+css+js打包成只有一套，然后前端请求的时候直接把所有的资源请求过来
    -   然后浏览器进行解析，然后我们首先直接进入默认设置好的主页，然后会有一些按钮
    -   如，我的，首页，然后这些按钮点击一下就会跳页面，然后由于配置了前端路由
    -   那么他就会去前端的路由表中查找，这个路由表中就记录着一个url对应的一个页面
    -   然后在把根据路由表中的对应页面的信息给展示出来
    -   **SPA最主要的特点就是在前后端分离的基础的上加了一层前端路由**
    -   **也就是前端来维护一套路由规则**
    -   **这个前端路由就是让我们改变url，但是页面不进行整体刷新**
-   **扩展**
    -   前端渲染与后端渲染
    -   前后端分离
-   早期的网站开发整个HTML .页面是由服务器来渲染的.
    -   服务器直接生产渲染好对应的HTML页面,返回给客户端进行展示.
-   但是,一个网站,这么多页面服务器如何处理呢?
    -   一个页面有自己对应的网址,也就是URL.
    -   URL会发送到服务器,服务器会通过正则对该URL进行匹配,并且最后交给一个Controller进行处理
    -   Controller进行各种处理,最终生成HTML或者数据,返回给前端.
    -   这就完成了一个IO操作
-   上面的这种操作,就是后端路由.
    -   当我们页面中需要请求不同的路径内容时，交给服务器来进行处理,服务器渲染好整个页面,并且将页面返回给客户端
    -   这种情况下渲染好的页面,不需要单独加载任何的js和Icss,可以直接交给浏览器展示,这样也有利于SEO的优化.
-   后端路由的缺点点
    -   一种情况是整个页面的模块由后端人员来编写和维护的.
    -   另一种情况是前端开发人员如果要开发页面,需要通过PHP和Java等语言来编写页面代码.
    -   而且通常情况下HTML代码和数据以及对应的逻辑会混在-起, 编写和维护都是非常糟糕的事情.





### 10.2、如可实现改变url但是页面不进行刷新

**通过改变hash来实现不刷新**

通过监听hash的改变来实现改变url而不进行刷新页面

然后通过hash的值去前端的路由映射里找我要渲染哪个组件，然后把它放到网页上

>   location.hash = ‘’

**通过history的pushState来改变url**

>   ![image-20210410130446042](G:\各科笔记\Vue笔记\Vue.assets\image-20210410130446042.png)
>
>   history.pushState()  => 压栈
>
>   history.back()  => 移除栈顶一个元素
>
>   history.go(-1) == history.back() 表示移除一个栈也可以写-2 也可为正
>
>   history.forward() == histroy.go(1)
>
>   浏览器的返回和前进就是用这种方式实现的



**通过history.replaceState来改变url**

>   history.pushState()  => 这个是通过替换上一个来实现url改变不刷新
>
>   使用这种方式后是不能返回上一步的

### 10.3、vue-router

-   目前前端流行的三大框架，都有自己的路由实现
    -   Angular的ngRouter
    -   React的ReactRouter
    -   Vue的vue-router
-   当然我们的重点是vue-router
    -   vue-router是Vue.js官方的路由插件,它和vue.js是深度集成的,适合用于构建单页面应用



-   **使用vue-router的步骤**
    -   第一步：创建路由组件
    -   第二步：配置路由的映射：组件和路径映射关系
    -   第三步：使用路由：通过<router-link>和<router-view>

>   **router-link标签是全局组件，是已经注册过的，它最终会被渲染成a标签**
>
>   ```js
>   // tag属性
>   // 指定将这个router-link标签渲染成一个button按钮
>   <router-link to='路径' tag='button'></router-link>  
>   
>   	// replaten不会留下history记录，指定replace的情况下后腿键返回的不能返回到上一个页面中
>   <router-link to='路径' replace></router-link>  
>   // 当<router-link>对应的路由匹配成功时，会自动给当前元素设置一个
>   // router-link-active的class样式
>   // 设置active-class可以修改默认的名称
>   <router-link active-class='active' ></router-link>  
>   // 可在路由index.js文件中统一配置linkActiveClass的名称
>   
>   
>   <style>
>       .active{
>           
>       }
>       </style>
>   ```
>
>   **router-view表示是指定组件需要展示的位置，它就是一个占位的标签**

**配置router的默认路径**

```js
// 在router的index.js中新增一个映射路径
 {
 // 将path的路径设置为缺省值 然后里的参数里面的 / 可加可不加
 	path: '',
 	// 重定向到的页面
 	redirect: ''
 }

```

### 10.4、通过代码跳转路由

```js
<template>
  <button @click="home">首页</buttom>
  <button @click="about">关于</buttom>
  <router-view></router-view>
</template>

<script>
export default {
	name: 'app',
        // 通过代码的方式修改路径
    methods: {
        home: {
            // 通过当前对象中内置的$router对象中的push跳转页面
            // push == pushState
            this.$router.push('/home')
            // 第二种方式
            // replace == replaceState
            this.$router.replace('/home')
        },
        about: {
            this.$router.push('/about')
        }
    }
}
</script>

<style>

</style>
```

### 10.5、动态路由

```js
// $route 当前哪个路由处于活跃状态那么拿到的就是哪个路由
// $router 是拿到我们自己创建的router文件中的index.js中的new router的对象
// 可以通过 this.$route.params.参数名 拿到路由传递过来的参数

```

### 10.6、路由的懒加载

​	当打包构建应用时，JavaScript包会变得非常大，影响页面加载

-   如果能把不同路由对应的组件分割成不同的代码块，然后当路由被访问的时候才加载对应的组件

-   这样就更加高效

    

>   **进一步解释**
>
>   1.  首先我们知道路由中会定义很多的不同的页面
>
>   2.  这个页面最后被打包是放在一个js文件夹中
>
>   3.  但是页面这么多放在一个js文件中，必然会造成这个页面非常大
>
>   4.  如果我们一次性从服务器请求下来这个页面，可能需要花费一定的时间，甚至出现短暂的空白
>
>   5.  然后要避免这种情况就需要使用路由懒加载
>
>       1.  **路由懒加载做了什么**
>
>           1.  路由懒加载的主要作用就是将路由对应组件打包一个 个的js代码块
>
>           2.  只有在这个路由被访问到的时候，才加载对应的组件
>
>           3.  写法如下：
>
>               ![image-20210410150301592](G:\各科笔记\Vue笔记\Vue.assets\image-20210410150301592.png)
>
>               ![image-20210410150319636](G:\各科笔记\Vue笔记\Vue.assets\image-20210410150319636.png)
>
>               ![image-20210410150516944](G:\各科笔记\Vue笔记\Vue.assets\image-20210410150516944.png)
>
>               

![image-20210410150544897](G:\各科笔记\Vue笔记\Vue.assets\image-20210410150544897.png)

​    

### 10.7、嵌套路由

-   实现嵌套路由有两个步骤
    -   创建对应的子组件，并且在路由映射中配置对应的子路由
    -   在组件内部使用<router-view>标签



```js
const HomeNews = () => import('文件路径')

{
    path: '/home',
    components: Home,
    children: [
        {
            path: '',
            redirect: 'news'
        },{
            path: 'news',
            components: HomeNews
        },{
            path: 'message',
            components: HomeMessage
        }
    ]
}
```

### 10.8、参数传递

```js
// params的类型
<router-view to="'/news/' + userId ">用户</router-view>

// 子组件接收
<script>
	export default {
		name: 'user',
        computed: {
            userId() {
                return this.$route.params.adb
            }
        }
	}    
</script>

// 需要配置动态路由
{
    path: '/user/:abc'
}
```

Vue.prototype 在vue的组件中添加的属性或者方法会作用在全局

##### 所有的组件都继承制Vue类的原型

#### query的类型传递参数

```js
// 如果要使用query的方式传递这个to后面必须是一个对象，不能是一个字符串
//<router-link to="'/news/' + userId ">用户</router-link>
// 如果要让to里面是一个对象必须加上v-bind，不然里面的东西都只会是一个字符串

// router-link与router-view 这两个标签在vue-router的源码中在vue中
// 注册了这俩个全局标签

// 然后这个对象可以写很多的属性
<router-link v-bind:to="{
	path: '/profile',
        // 如果需要传递多个参数使用query
    query: {
        name: 'wlp',
        age: 18,
        height: 188
    }
}">用户</router-link>

// 取值
$route.query.属性
$route.query => 显示所有的属性

// 按钮方式跳转页面传递参数
methods: {
    userCilck() {
        this.$router.push('/user' + this.userId)
    },
    profileClick() {
        this.$router.push({
            path: '/profile',
            query: {
                name: 'kon',
                age: 18
            }
        })
    }
}
```

### 10.9、导航卫士

如果改变网页的标签

-   网页标题是通过<title>来显示的，但是SPA只有一个固定的HTML，切换不同的页面时

    -   标题并不会改变
    -   使用JavaScript来修改<title>的内容.window.document.title

-   vue-router提供的导航守卫主要用来监听监听路由的进入和离开

-   vue-router提供beforeEach和afterEach的钩子函数，它们会在路由即将改变前和改变后触发

-   ##### 扩展

    -   **Scheme协议**
        -   设置Android：scheme = ‘http’
        -   统一资源定位符的标准格式
        -   协议类型: [//服务器地址 [:端口号]] [/资源层级Unix文件路径]文件名\[?查询\][#片段]
        -   ![image-20210412110006028](G:\各科笔记\Vue笔记\Vue.assets\image-20210412110006028.png)

##### 路由独享守卫

```js
const router = new VueRouter({
  routes: [
    {
      path: '/foo',
      component: Foo,
      beforeEnter: (to, from, next) => {
        // ...
      }
    }
  ]
})
```



**created() 当这个组件被创建出来时回调这个生命周期函数**

-   可以通过：**document.title = ‘标题’** => 更改标题

**mounted() 当这个组件的中的template中的html内容被挂载到dom上时回调这个函数**

**updated() 当界面发生更新的时候回调函数**

```js
// 通过router创建一个全局守卫
// 前置钩子（hook）
router.brforeEach((to,from,next) => {
    // to: 即将要进入的目标的路由对象
    // from: 当前导航即将要离开的路由对象
    // next: 调用该方法后，才能进入下一个钩子
    document.title = to.meta.title
    next()
    // 设置默认首页title
    document.title = to.matched[0].meta.title
})

// 后置钩子（hook）
router.afterEach((to,from){
    
})
```



-     	meta元数据
-   从from跳转到to

### 10.10、keep-alive

**keep-alive是Vue内置的一个组件，可以使被包含的组件保留状态，或避免重新渲染**

**router-view也是一个组件 ，如果直接被包在keep-alive里面，所有路径匹配到的视图组件都会被缓存**

```vue
当我们离开界面然后在返回这个界面需要保留之前界面的状态

// 当我们离开组件的时候会销毁这个组件
// 进入组件的时候又会被创建
<template>
  <div id="app">
    <img src="./assets/logo.png" />
    <router-link to='/test'>测试</router-link>
// exclude里面写的是name,使用逗号隔开多个组件  include
	<keep-alive exclude="Profile,User">
    	<router-view />    
    </keep-alive>

	<keep-alive>
    	<router-view>
        	// 所有路径匹配到的视图组件都会被缓存
        </router-view>    
    </keep-alive>
  </div>
</template>

<script>
exprot default {
	name: 'Profile',
	data() {
        return {
            message: '',
            // 使用path属性记录离开时的路径，在beforeRouteLeave中记录
            path: '/home'
        }
    },
	// 当组件创建完成后回调,只会调用一次
	created() {
        
    },
	// 当组件销毁时回调
	destroyed() {
        
    },
        // 这个方法执行的条件router-view必须放置在keep-alive标签中
        // 否则无效
    activated() {
        // 当这个界面处于活跃状态调用
        this.$router.push(this.path)
    }
		// 这个方法执行的条件router-view必须放置在keep-alive标签中
        // 否则无效
	deactivated() {
        // 当这个界面处于不活跃状态调用
    },
    beforRouteLeave(to,form,next) {
        // 组件内导航 记录当前路由路径
        this.path = this.$route.path;
        next()
    }
    }
</script>
```

**keep-alive是Vue内置的一个组件，可以使被包含的组件保留状态，或避免重新渲染**

-   keep-alive有俩个重要属性
    -   include  - 字符串或正则表达，只有匹配的组件会被缓存
    -   exclude - 字符串或正则表达式，任何匹配的组件都不会被缓存
-   router-view 也是一个组件，如果直接被包在keep-alive里面，所有路径匹配到视图组件都会被缓存



### 10.11 TabBar案例





## 11、Promise



### 1、什么是Promis

**Promise是异步编程的一种解决方案**

**什么时候会使用到？**

>   一般情况下是有异步操作时，使用promise对这个异步操作进行封装

-   一种很常见的

![image-20210413215807076](G:\各科笔记\Vue笔记\Vue.assets\image-20210413215807076.png)

### 2、案例

```js
<script>
    // 1、使用setTimeout函数 
    // 设置在几秒钟之后回调其中函数中定义的代码

    // new 一个promise需要传入一个函数
    // 这个函数有俩个参数，这个俩个参数也是一个函数
    // resolve: 解决
    // reject：拒绝
    // then: 下一步
    new Promise((resolve,reject) =>{
    setTimeout(() =>{
        resolve()
    },1000)
}).then(() =>{
    console.log('hello world')
    console.log('hello world')
    console.log('hello world')
    console.log('hello world')
    console.log('hello world')

    return new Promise((resole,reject) =>{
        setTimeout(() =>{
            resolve()
        },1000)
    }).then(() =>{

        console.log('hello world')
        console.log('hello world')
        console.log('hello world')
        console.log('hello world')
        console.log('hello world')

        return new Promise((resole,reject) =>{

        }
                           })
    })
</script>
```



### 3、Promise的三种状态

1.  pending：等待状态
    1.  比如正在进行网络请求，或者定时器没有到时间
2.  fulfill：满足状态
    1.  当我们主动回调resolve时，就处于该状态，并且会回答then
3.  reject：拒绝状态
    1.  当我们主动回调了reject时，就除与该状态，并且会回调catch（）



### 4、链式调用简写

![image-20210414081401425](G:\各科笔记\Vue笔记\Vue.assets\image-20210414081401425.png)

```js
<script>
    new Promise((resole,reject) =>{
    setTimeout(() =>{
        resolve('aaa')
    },1000)
}).then(res =>{
    // 1.自己处理10行代码
    console.log(res + '一')

    // 2.对结果进行第一次处理
    return new Promise((resolve) =>{
        resolve(res + '二')
    })
}).then(res =>{
    // 第二层的代码处理
    console.log(res + '')

    return new Promise(resolve =>{
        resolve(res + '22')
    })
}).then(res =>{
    // 第三层的代码处理
    console.log(res)
})
</script>
```









##### [报错](#目录)

1、Vue项目中，Cannot find module 'node-sass' 报错找不到解决方法！！！！！

>   运行命令：
>
>   cnpm install node-sass@latest  
>
>   即可解决，（ 网络差的同学可以选择重新下载no-modules



















![image-20210329104826698](G:\各科笔记\Vue笔记\Vue.assets\image-20210329104826698.png)

![image-20210329110248873](G:\各科笔记\Vue笔记\Vue.assets\image-20210329110248873.png)









































![image-20210328203527438](G:\各科笔记\Vue笔记\Vue.assets\image-20210328203527438.png)

























![image-20210328155615697](G:\各科笔记\Vue笔记\Vue.assets\image-20210328155615697.png) 







![image-20210328153314496](G:\各科笔记\Vue笔记\Vue.assets\image-20210328153314496.png)























![image-20210328152029787](G:\各科笔记\Vue笔记\Vue.assets\image-20210328152029787.png)

![image-20210328152116809](G:\各科笔记\Vue笔记\Vue.assets\image-20210328152116809.png)

![image-20210328152133879](G:\各科笔记\Vue笔记\Vue.assets\image-20210328152133879.png)



![image-20210328152206252](G:\各科笔记\Vue笔记\Vue.assets\image-20210328152206252.png)

![image-20210328152235099](G:\各科笔记\Vue笔记\Vue.assets\image-20210328152235099.png)



![image-20210328152259582](G:\各科笔记\Vue笔记\Vue.assets\image-20210328152259582.png)



![image-20210328152355834](G:\各科笔记\Vue笔记\Vue.assets\image-20210328152355834.png)





![image-20210328151538772](G:\各科笔记\Vue笔记\Vue.assets\image-20210328151538772.png)

![image-20210328151829022](G:\各科笔记\Vue笔记\Vue.assets\image-20210328151829022.png)







## 环境安装

第二个安装依赖环境





![image-20210328134350775](G:\各科笔记\Vue笔记\Vue.assets\image-20210328134350775.png)

![image-20210328150338521](G:\各科笔记\Vue笔记\Vue.assets\image-20210328150338521.png)



![image-20210328135315496](G:\各科笔记\Vue笔记\Vue.assets\image-20210328135315496.png)

![image-20210328135828568](G:\各科笔记\Vue笔记\Vue.assets\image-20210328135828568.png)

![image-20210328140317597](G:\各科笔记\Vue笔记\Vue.assets\image-20210328140317597.png)