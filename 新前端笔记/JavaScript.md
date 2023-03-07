# 原生 JavaScript



### 1、访问DOM

#### `getElementById()` ：

-   >   根据`id`获取元素对象（一个）

    -   ```javascript
        <div id="countdown"><div>
        document.getElementById('countdown')
        ```

#### `querySelector()`：

-   >   返回匹配的CSS选择器的一个元素（一个）

    -   ```javascript
        <a class="logo" href="#">吃了吗</a>
        document.querySelector('.logo')
        document.querySelector('a')
        document.querySelector('a.logo') 	class为logo的第一个a标签元素
        ```

#### `querySelectorAll()`：

-   >   返回匹配 CSS 选择器的所有元素（一个或多个）

    - ```javascript
        <section id="again" class="banner" role="banner" name='test'>
        document.querySelectorAll('#again')
        document.querySelectorAll('.banner')
        document.querySelectorAll('section')
        ```

#### `getElementsByClassName()` ：

- >   返回所有指定类名的元素集合（多个）

    - ```javascript
        document.getElementsByClassName("logo");
        ```

#### `getElementsByTagName()` ：

- >   返回带有指定标签名的**对象**集合（多个）

    - ```javascript
        <section class="banner" role="banner">
        document.getElementsByTagName('section')
        ```

#### `parentNode` ：

- >   获取父元素集合（一个）

    - ```javascript
        var countdown =  document.getElementById('countdown')
        countdown.parentNode
        ```

#### `children`：

- >   获取子元素集合

    - ```javascript
        var countdown =  document.getElementById('countdown')
        countdown.children
        ```

#### `firstChild`：

- >   获取第一个子元素

    - ```javascript
        var countdown =  document.getElementById('countdown')
        countdown.firstChild
        ```

#### `lastChild`：

- >   获取最后一个子元素

    - ```javascript
        var countdown =  document.getElementById('countdown')
        countdown.lastChild
        ```

#### `previousSibling` ：

- >   获取前面的兄弟节点

    - ```javascript
        var countdown =  document.getElementById('countdown')
        countdown.previousSibling
        ```

#### `nextSibling` ：

- >   获取后面的兄弟节点

    - ```javascript
        var countdown =  document.getElementById('countdown')
        countdown.nextSibling 
        ```

**document对象避免使用的节点对象和属性：**

```javascript
document.attributes			文档没有该属性
document.hasAttributes()	文档没有该属性
document.nextSibling		文档没有下一节点
document.nodeName			这个通常是 #document
document.nodeType			这个通常是 9
document.nodeValue			文档没有一个节点值
document.ownerDocument		文档没有主文档
document.ownerElement		文档没有自己的节点
document.parentNode			文档没有父节点
document.previousSibling	文档没有兄弟节点
document.textContent		文档没有文本节点
```



### 2、操作DOM

#### `appendChild()` ：

- >   追加元素到的子节点的最后面

    - ```javascript
        var node = document.createTextNode("滴滴滴滴");
        document.body.appendChild(node);
        ```

#### `insertBefore`：

- >   将某个节点插入到另外一个节点的前面

    - ```javascript
        var node = document.createTextNode("滴滴滴滴");
        parentNode.insertBefore(node, Element)	将node插入到Element前面
        ```

#### `removeChild()`：

- >   删除指定的子节点并返回子节点

    - ```javascript
        var deletedChild = parent.removeChild(node);		// deletedChild 存储被删除的节点
        ```

#### `replaceChild`：

- >   将一个节点替换另一个节点

    - ```javascript
        parent.replaceChild(newChild, oldChild);
        ```

#### `createElement()` ：

- >   创建元素

    - ```javascript
        var elem = document.createElement("div");
        ```

#### `createTextNode()`：

- >   创建文本节点

    - ```javascript
        var node = document.createTextNode("滴滴滴滴");
        ```

#### ` cloneNode`：

- >   克隆一个节点，接收一个bool参数，用来表示是否复制子元素

    - ```javascript
        var from = document.getElementById("test");
        var clone = from.cloneNode(true);
        clone.id = "test2";
        document.body.appendChild(clone);
        ```

#### `nodeValue`：

- >   返回节点值

    - ```javascript
        <button onclick="myFunction()">点我</button>
        
        function myFunction(){
        	var c=document.getElementsByTagName("button")[0];
        	var x=document.getElementById("demo");  
        	x.innerHTML=c.childNodes[0].nodeValue;
        }
        ```

#### `innerHTML` ：

- >   以html解析插入内容

    - ```javascript
        var div = document.getElementById("div");
        div.innerHTML = "<h1>hello</h1>";
        ```

#### `innerText`：

- >   以txt解析插入内容

    - ```javascript
        var div = document.getElementById("div");
        div.innerHTML = "<h1>hello</h1>";
        ```

#### `textContent` ：

- >   设置文本内容

    - ```javascript
        <a class="logo" href="#">吃了吗</a>
        var logo = document.querySelector('.logo')
        logo.textContent				// 获取文本值
        logo.textContent = '吃了吗'	  // 设置文本的值
        ```

#### `className`：

- >   设置标签的class属性

    - ```javascript
        <section id="again" class="banner" role="banner" name='test'></section>
        var again = document.getElementById('again')
        again.className				// 获取class的值
        again.className = 'yyyyy'	// 设置class的值
        ```

#### `id` ：

- >   设置标签的id属性

    - ```javascript
        var elem = document.createElement("div");
        elem.id = 'test';
        ```

#### `hasAttribute()`：

- >   判断是否有指定的属性存在

    - ```javascript
        var elem = document.createElement("div");
        elem.hasAttribute("onclick");
        ```

#### `getAttribute()` ：

- >   通过名称获取属性的值

    - ```javascript
        <section id="again" class="banner" role="banner" name='test'></section>
        var section = document.getElementById('again')
        section.getAttribute('name')
        section.getAttribute('class')
        section.getAttribute('id')
        ```

#### `setAttribute()` ：

- >   通过名称设置属性的值

    - ```javascript
        <section id="again" class="banner" role="banner" name='test'></section>
        var section = document.getElementById('again')
        section.setAttribute('name','yyyyy')
        section.setAttribute('class','yyyyy')
        ```

#### `removeAttribute()`：

- >   删除属性

    - ```javascript
        <section id="again" class="banner" role="banner" name='test'></section>
        var section = document.getElementById('again')
        section.removeAttribute('name')
        section.removeAttribute('class')
        ```

#### `element.sytle.xxx（只能获取到内联样式）`：

- >   添加、修改、删除元素样式

    - ```javascript
        <section id="again" class="banner" role="banner" name='test'></section>
        var section = document.getElementById('again')
        section.style.color = 'red';
        section.style.setProperty('font-size', '16px');
        section.style.removeProperty('color');
        ```

    - `动态添加样式规则`

    - ```javascript
        var style = document.createElement('style');
        style.innerHTML = 'body{color:red} #top:hover{background-color: red;color: white;}';
        document.head.appendChild(style);
        ```

#### `getBoundingClientRect`：

- >   返回元素的大小以及相对于浏览器可视窗口的位置

    - ```javascript
        <section id="again" class="banner" role="banner" name='test'></section>
        var section = document.getElementById('again')
        section.getBoundingClientRect()
        ```

#### `prompt`：

- >   弹框获取输入的值

    - ```javascript
        var tall = prompt("请输入代办事项","");
        ```




#### `添加节点案例`

```javascript
<div id="todoItemBox" class="todoItemBox">
    <div class="todoItemBar">待办事项列表<a href="javascript:addToDo()">+</a></div>
</div>

function addToDo() {
    var tall = prompt("请输入代办事项",""); // 弹框获取值
    var text = "<input type='checkbox'>"+ tall +"<a href='javascript: void(0);' onclick='deleteToDo(this)'></a>";

    var div = document.createElement('div');	// 创建一个div节点
    div.setAttribute('class', 'todoItem');	// 设置样式
    div.innerHTML = text;	// 把text内容以html识别写入div中

    var node = document.getElementById('todoItemBox')	// 放置位置

    node.appendChild(div)       // 在默认添加节点
}
```



#### `删除节点案例`

```javascript
<div id="todoItemBox" class="todoItemBox">
    <div class="todoItem">
        <input type="checkbox">整理房间<a href="javascript:void(0);" onclick="deleteToDo(this)"></a>
    </div>
</div>
function deleteToDo(self) {

    //请在这里完善代码
    let div = document.getElementById('todoItemBox');
    div.removeChild(self.parentNode);
}
```



### 3、事件处理

#### 

###### **UI事件**：

- `load` 
- `unload`
- `error` 
- `resize`
- `scroll`

###### **键盘事件**：

- `keydown` 
- `keyup` 
- `keypress`

###### **鼠标事件**：

- `click` 
- `dbclick`
- `mousedown`
- `mouseup` 
- `mousemove` 
- `mouseover` 
- `mouseout`

###### **焦点事件**：

- `focus` 
- `blur`

###### **表单事件**：

- `input` 
- `change` 
- `submit` 
- `reset` 
- `cut` 
- `copy` 
- `paste` 
- `select`

#### 事件对象（低版本IE中的window.event）

- `target`（有些浏览器使用srcElement）
- `type`
- `cancelable`
- `preventDefault()`
- `stopPropagation()`（低版本IE中的cancelBubble）

#### 鼠标事件 - 事件发生的位置

- 屏幕位置：
    - `screenX`
    - `screenY`
- 页面位置：
    - `pageX`
    - `pageY`
- 客户端位置：
    - `clientX`
    - `clientY`

#### 键盘事件 - 哪个键被按下了

- `keyCode`属性
    - 有些浏览器使用`which`
- `String.fromCharCode(event.keyCode)`

#### HTML5事件

- `DOMContentLoaded`
- `hashchange`
- `beforeunload`