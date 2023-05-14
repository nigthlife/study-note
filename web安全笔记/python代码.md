## BeautifulSoup库使用

>   BeautifulSoup库是Python中一个非常流行的HTML和XML解析库。
>
>   它可以从HTML或XML文档中提取数据，使得数据提取更加方便快捷

**假设我们有一个包含以下HTML代码的文件`example.html`**

```xml
<!DOCTYPE html>
<html>
<head>
	<title>Example Page</title>
</head>
<body>
	<h1>Welcome to my website!</h1>
	<p>Here is some information about me:</p>
	<ul>
		<li>Name: John Smith</li>
		<li>Age: 30</li>
		<li>Occupation: Web Developer</li>
	</ul>
</body>
</html>
```

**我们可以使用如下代码来解析这个HTML文件**

```py
from bs4 import BeautifulSoup

# 读取HTML文件内容
with open('example.html', 'r') as file:
    html = file.read()

# 解析HTML文件内容
soup = BeautifulSoup(html, 'html.parser')

# 获取页面标题
title = soup.title.string

# 获取页面主体内容
body = soup.body

# 获取姓名、年龄和职业信息
name = soup.find('li', text='Name:').string.split(':')[1].strip()
age = soup.find('li', text='Age:').string.split(':')[1].strip()
occupation = soup.find('li', text='Occupation:').string.split(':')[1].strip()

# 输出结果
print('Title:', title)
print('Name:', name)
print('Age:', age)
print('Occupation:', occupation)
# 输出结果为:
# Title: Example Page
# Name: John Smith
Age: 30
Occupation: Web Developer

```



## 证书验证解决

**（同时适用urlopen和urlretrieve函数）：**

```python
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
```

**（适用于urlopen函数,因为urlretrieve没有context参数所以不适用）：**

```python
import ssl
context = ssl._create_unverified_context()
response = urlopen(json_url, context=context)
```

## 获取验证码

```python
import ddddocr

ocr = ddddocr.DdddOcr()
with open('1.png', 'rb') as f:
    img_bytes = f.read()
res = ocr.classification(img_bytes)

print(res)
```

## 会话维持

```python
s=requests.Session()
s.get('http://httpbin.org/cookies/set/number/123456789')
r=s.get('http://httpbin.org/cookies')
print(r.text)

```

## 写入文件

**多行写入（如html）**

```python
data = ['a','b','c']
#单层列表写入文件
with open("data.txt","w") as f:
    f.writelines(data)
```



