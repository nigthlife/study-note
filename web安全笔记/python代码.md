## 1、证书验证解决

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

## 2、获取验证码

```python
import ddddocr

ocr = ddddocr.DdddOcr()
with open('1.png', 'rb') as f:
    img_bytes = f.read()
res = ocr.classification(img_bytes)

print(res)
```

## 3、会话维持

```python
s=requests.Session()
s.get('http://httpbin.org/cookies/set/number/123456789')
r=s.get('http://httpbin.org/cookies')
print(r.text)

```

## 4、写入文件

**多行写入（如html）**

```python
data = ['a','b','c']
#单层列表写入文件
with open("data.txt","w") as f:
    f.writelines(data)
```



