

[TOC]



###Html5

	HTML5 是定义 HTML 标准的最新的版本。 该术语表示两个不同的概念：
		它是一个新版本的HTML语言，具有新的元素，属性和行为，
		它有更大的技术集，允许更多样化和强大的网站和应用程序。
				这个集合有时称为HTML5和朋友，通常缩写为HTML5。
	
		HTML5     约等于     HTML + CSS + JS

###Html5优势

	跨平台:唯一一个通吃PC MAC Iphone Android等主流平台的跨平台语言
	快速迭代
	降低成本
	导流入口多
	分发效率高

###根元素

	H4中的根元素:
		<html xmlns="http://www.w3.org/1999/xhtml">
		
		首先这个标记没有任何问题，你喜欢的话,那就背下来继续用。它是有效的。
		但这个标记中的很多字节在Html5中我们都可以省略了
		
		xmlns:这是XHTML1.0的东西，
			它的意思是在这个页面上的元素都位于http://www.w3.org/1999/xhtml这个命名空间内
			但是HTML5中的每个元素都具有这个命名空间，不需要在页面上再显示指出


​			

	H5中的根元素
		<html></html>

###head元素

	MIME类型:
		每当浏览器请求一个页面时，web服务器会在发送实际页面内容之前，先发送一些头信息。
		浏览器需要这些信息来决定如何解析随后的页面内容。最重要的是Content-Type
		
		比如: Content-Type:text/html
		
		text/html:即这个页面的"内容类型",或者称为MIME类型。这个头信息将唯一确定某个资源的本质是什么
		也决定了它应该如何被呈现。
		
		图片也有自己的MIME类型		
			jpg:image/jpeg   
			png:image/png
			
		js也有自己的MIME类型，css也有自己的MIME类型，
			任何资源都有自己的MIME类型，整个web都依靠MIME类型来运作


​			
​			

	<meta charset="UTF-8">:
		告诉浏览器你应该使用哪种编码来解析网页

###语义化标签

	在HTML 5出来之前，我们用div来表示页面头部，章节，页脚等。但是这些div都没有实际意义。
	各大浏览器厂商分析了上百万的页面，从中发现了DIV名称的通用id名称大量重复。例如，很多开发人员喜欢使用
	div id="footer"来标记页脚内容，所以Html5元素引入了语义化标签（一组新的片段类元素）
	
	https://dev.opera.com/blog/presentation-html5-and-accessibility-sitting-in-a-tree-4/idlist-url.htm
	https://dev.opera.com/blog/presentation-html5-and-accessibility-sitting-in-a-tree-4/classlist-url.htm
	
	<hgroup></hgroup>
	<header></header>
	<nav></nav>
	<section></section>
	<footer></footer>
	<article></article>
	<aside></aside>


​	

	语义化的好处
		HTML5可以让很多更语义化结构化的代码标签代替大量的无意义的div标签
		这种语义化的特性提升了网页的质量和语义
		对搜索引擎更加的友好
	他们这些标签功能就是代替<div>功能中的一部分，他们没有任何的默认样式，除了会让文本另起一行外；
	https://gsnedders.html5.org/outliner/


​	

	hgroup元素代表 网页 或 section 的标题，当元素有多个层级时，该元素可以将h1到h6元素放在其内，譬如文章的主标题和副标题的组合
	
		<hgroup>
		    <h1>HTML 5</h1>
		    <h2>这是一篇介绍HTML 5语义化标签和更简洁的结构</h2>
		</hgroup>
	
		hgroup使用注意：
			如果只需要一个h1-h6标签就不用hgroup
			如果有连续多个h1-h6标签就用hgroup
			如果有连续多个标题和其他文章数据，h1-h6标签就用hgroup包住，和其他文章元数据一起放入header标签


​	

	header 元素代表 网页 或 section 的页眉。
		通常包含h1-h6元素或hgroup
	
		<header>
		    <hgroup>
		        <h1>网站标题</h1>
		        <h2>网站副标题</h2>
		    </hgroup>
		</header>
		
		header使用注意：
			可以是“网页”或任意“section”的头部部分
			没有个数限制。
			如果hgroup或h1-h6自己就能工作的很好，那就不要用header。



	nav元素代表页面的导航链接区域。用于定义页面的主要导航部分。
	
		<nav>
		    <ul>
		        <li>HTML 5</li>
		        <li>CSS3</li>
		        <li>JavaScript</li>
		    </ul>
		</nav>
		
		nav使用注意：
			用在整个页面主要导航部分上，不合适就不要用nav元素；


​	
​	

	section元素代表文档中的 节 或 段，段可以是指一篇文章里按照主题的分段；节可以是指一个页面里的分组。
	
		<section>
		    <h1>section是啥？</h1>
		    <article>
		        <h2>关于section</h1>
		        <p>section的介绍</p>
		        <section>
		            <h3>关于其他</h3>
		            <p>关于其他section的介绍</p>
		        </section>
		    </article>
		</section>
		
		section使用注意：
			section不是一般意义上的容器元素，如果想作为样式展示和脚本的便利，可以用div。
			article、nav、aside可以理解为特殊的section，
			所以如果可以用article、nav、aside就不要用section，没实际意义的就用div		


​		
​		

	article元素最容易跟section和div容易混淆，其实article代表一个在文档，页面或者网站中自成一体的内容
	
		<article>
		    <h1>一篇文章</h1>
		    <p>文章内容..</p>
		    <footer>
		        <p><small>版权：html5jscss网所属，作者：damu</small></p>
		    </footer>
		</article>
		
		article使用注意：
			独立文章：用article
			单独的模块：用section
			没有语义的：用div


​		
​		

	aside元素被包含在article元素中作为主要内容的附属信息部分，其中的内容可以是与当前文章有关的相关资料、标签、名次解释等
		
		在article元素之外使用作为页面或站点全局的附属信息部分。最典型的是侧边栏，其中的内容可以是日志串连，其他组的导航，甚至广告，这些内容相关的页面。
		
		<article>
		    <p>内容</p>
		    <aside>
		        <h1>作者简介</h1>
		        <p>小北，前端一枚</p>
		    </aside>
		</article>
		
		aside使用总结：
			aside在article内表示主要内容的附属信息，
			在article之外则可做侧边栏
			如果是广告，其他日志链接或者其他分类导航也可以用


​	
​	
​	

	footer元素代表 网页 或 section 的页脚，通常含有该节的一些基本信息，譬如：作者，相关文档链接，版权资料。
	
		<footer>
		    COPYRIGHT@damu
		</footer>
		
		footer使用注意：
			可以是 网页 或任意 section 的底部部分；
			没有个数限制，除了包裹的内容不一样，其他跟header类似。

