import json
import requests

j_data = '''
[{
"id": "ba1van4",
"intro": "21级 / 不会Re / 不会美工 / 活在梦里 / 喜欢做不会的事情 / ◼◻粉",
"url": "https://ba1van4.icu"
},
{
"id": "yolande",
"intro": "21级 / 非常菜的密码手 / 很懒的摸鱼爱好者，有点呆，想学点别的但是一直开摆",
"url": "https://y01and3.github.io/"
},
{
"id": "t0hka",
"intro": "21级 / 日常自闭的Re手",
"url": "https://blog.t0hka.top/"
},
{
"id": "h4kuy4",
"intro": "21级 / 菜鸡pwn手 / 又菜又爱摆",
"url": "https://hakuya.work"
},
{
"id": "kabuto",
"intro": "21级web / cat../../../../f*",
"url": "https://www.bilibili.com/video/BV1GJ411x7h7/"
},
{
"id": "R1esbyfe",
"intro": "21级 / 爱好歪脖 / 究极咸鱼一条 / 热爱幻想 / 喜欢窥屏水群",
"url": "https://r1esbyfe.top/"
},
{
"id": "tr0uble",
"intro": "21级 / 喜欢肝原神的密码手",
"url": "https://clingm.top"
},
{
"id": "Roam",
"intro": "21级 / 入门级crypto",
"url": "#"
},
{
"id": "Potat0",
"intro": "20级 / 摆烂网管 / DN42爱好者",
"url": "https://potat0.cc/"
},
{
"id": "Summer",
"intro": "20级 / 歪脖手 / 想学运维 / 发呆业务爱好者",
"url": "https://blog.m1dsummer.top"
},
{
"id": "chuj",
"intro": "20级 / 已退休不再参与大多数赛事 / 不好好学习，生活中就会多出许多魔法和奇迹",
"url": "https://cjovi.icu"
},
{
"id": "4nsw3r",
"intro": "20级会长 / re / 不会pwn",
"url": "https://4nsw3r.top/"
},
{
"id": "4ctue",
"intro": "20级 / 可能是IOT的MISC手 / 可能是美工 / 废物晚期",
"url": "#"
},
{
"id": "0wl",
"intro": "20级 / Re手 / 菜",
"url": "https://0wl-alt.github.io"
},
{
"id": "At0m",
"intro": "20级 / web / 想学iot",
"url": "https://homeboyc.cn/"
},
{
"id": "ChenMoFeiJin",
"intro": "20级 / Crypto / 摸鱼学代师",
"url": "https://chenmofeijin.top"
},
{
"id": "Klrin",
"intro": "20级 / WEB / 菜的抠脚 / 想学GO",
"url": "https://blog.mjclouds.com/"
},
{
"id": "ek1ng",
"intro": "20级 / Web / 还在努力",
"url": "https://ek1ng.com"
},
{
"id": "latt1ce",
"intro": "20级 / Crypto&BlockChain / Plz V me 50 eth",
"url": "https://lee-tc.github.io/"
},
{
"id": "Ac4ae0",
"intro": "*级 / 被拐卖来接盘的格子 / 不可以乱涂乱画哦",
"url": "https://twitter.com/LAttic1ng"
},
{
"id": "Akira",
"intro": "19级 / 不会web / 半吊子运维 / 今天您漏油了吗",
"url": "https://4kr.top"
},
{
"id": "qz",
"intro": "19级 / 摸鱼美工 / 学习图形学、渲染ing",
"url": "https://fl0.top/"
},
{
"id": "Liki4",
"intro": "19级 / 脖子笔直歪脖手",
"url": "https://github.com/Liki4"
},
{
"id": "0x4qE",
"intro": "19级 / &lt;/p&gt;&lt;p&gt;Web",
"url": "https://github.com/0x4qE"
},
{
"id": "xi4oyu",
"intro": "19级 / 骨瘦如柴的胖手",
"url": "https://www.xi4oyu.top/"
},
{
"id": "R3n0",
"intro": "19级 / bin底层选手",
"url": "https://r3n0.top"
},
{
"id": "m140",
"intro": "19级 / 不会re / dl萌新 / 太弱小了，没有力量 / 想学游戏",
"url": "#"
},
{
"id": "Mezone",
"intro": "19级 / 普通的binary爱好者。",
"url": "#"
},
{
"id": "d1gg12",
"intro": "19级 / 游戏开发 / 🐟粉",
"url": "https://d1g.club"
},
{
"id": "Trotsky",
"intro": "19级 / 半个全栈 / 安卓摸🐟 / P 社玩家 / 🍆粉",
"url": "https://altonhe.github.io/"
},
{
"id": "Gamison",
"intro": "19级 / 挖坑不填的web选手",
"url": "http://aw.gamison.top"
},
{
"id": "Tinmix",
"intro": "19级会长 / DL爱好者 / web苦手",
"url": "http://poi.ac"
},
{
"id": "RT",
"intro": "19级 / Re手，我手呢？",
"url": "https://wr-web.github.io"
},
{
"id": "wenzhuan",
"intro": "18 级 / 完全不会安全 / 一个做设计的鸽子美工 / 天天画表情包",
"url": "https://wzyxv1n.top/"
},
{
"id": "Cosmos",
"intro": "18级 / 莫得灵魂的开发 / 茄粉 / 作豚 /  米厨",

"url": "https://cosmos.red"
},
{
"id": "Y",
"intro": "18 级 / Bin / Win / 电竞缺乏视力 / 开发太菜 / 只会 C / CSGO 白给选手",
"url": "https://blog.xyzz.ml:444/"
},
{
"id": "Annevi",
"intro": "18级 / 会点开发的退休web手 / 想学挖洞 / 混吃等死",
"url": "https://annevi.cn"
},
{
"id": "logong",
"intro": "18 级 / 求大佬带我IoT入门 / web太难了只能做做misc维持生计 / 摸🐟",
"url": "http://logong.vip"
},
{
"id": "Kevin",
"intro": "18 级 / Web / 车万",
"url": "https://harmless.blue/"
},
{
"id": "LurkNoi",
"intro": "18级 / 会一丢丢crypto / 摸鱼",
"url": "#"
},
{
"id": "幼稚园",
"intro": "18级会长 / 二进制安全 /  干拉",
"url": "https://danisjiang.com"
},
{
"id": "lostflower",
"intro": "18级 / 游戏引擎开发 / 尚有梦想的game maker",
"url": "https://r000setta.github.io"
},
{
"id": "Roc826",
"intro": "18 级 / Web 底层选手",
"url": "http://www.roc826.cn/"
},
{
"id": "Seadom",
"intro": "18 级 / Web / 真·菜到超乎想象 / 拼死学（mo）习（yu）中",
"url": "#"
},
{
"id": "ObjectNotFound",
"intro": "18级 / 懂点Web & Misc / 懂点运维 / 正在懂游戏引擎 / 我们联合！",
"url": "https://www.zhouweitong.site"
},
{
"id": "Moesang",
"intro": "18 级 / 不擅长 Web / 擅长摸鱼 / 摸鱼！",
"url": "https://blog.wz22.cc"
},
{
"id": "E99p1ant",
"intro": "18级 / 囊地鼠饲养员 / 写了一个叫 Cardinal 的平台",
"url": "https://github.red/"
},
{
"id": "Michael",
"intro": "18 级 / Java / 会除我佬",
"url": "http://michaelsblog.top/"
},
{
"id": "matrixtang",
"intro": "18级 / 编译器工程师( 伪 / 半吊子PL- 静态分析方向",
"url": "#"
},
{
"id": "r4u",
"intro": "18级 / 不可以摸🐠哦",
"url": "http://r4u.top/"
},
{
"id": "357",
"intro": "18级 / 并不会web / 端茶送水选手",
"url": "#"
},
{
"id": "Li4n0",
"intro": "17 级 / Web 安全爱好者 / 半个程序员 / 没有女朋友",
"url": "https://blog.0e1.top"
},
{
"id": "迟原静",
"intro": "17级 / Focus on Java Security",
"url": "#"
},
{
"id": "Ch1p",
"intro": "17 级 / 自称 Bin 手实际啥都不会 / 二次元安全",
"url": "http://ch1p.top"
},
{
"id": "f1rry",
"intro": "17 级 / Web",
"url": "#"
},
{
"id": "mian",
"intro": "17 级 / 业余开发 / 专业摸鱼",
"url": "https://www.intmian.com"
},
{
"id": "ACce1er4t0r",
"intro": "17级 / 摸鱼ctfer / 依旧在尝试入门bin / 菜鸡研究生+1",
"url": "#"
},
{
"id": "MiGo",
"intro": "17级 / 二战人 / 老二次元 / 兴趣驱动生活",
"url": "https://migoooo.github.io/"
},
{
"id": "BrownFly",
"intro": "17级 / RedTeamer / 字节跳动安全工程师",
"url": "https://brownfly.github.io"
},
{
"id": "Aris",
"intro": "17级/ Key厨 / 腾讯玄武倒水的",
"url": "https://blog.ar1s.top"
},
{
"id": "hsiaoxychen",
"intro": "17级 / 游戏厂打工仔 / 来深圳找我快活",
"url": "https://chenxy.me"
},
{
"id": "Lou00",
"intro": "17级 / web / 东南读研",
"url": "https://blog.lou00.top"
},
{
"id": "Junier",
"intro": "16 级 / 立志学术的统计er / R / 为楼上的脱单事业做出了贡献",
"url": "#"
},
{
"id": "bigmud",
"intro": "16 级会长 / Web 后端 / 会一点点 Web 安全 / 会一丢丢二进制",
"url": "#"
},
{
"id": "NeverMoes",
"intro": "16 级 / Java 福娃 / 上班 996 / 下班 669",
"url": "#"
},
{
"id": "Sora",
"intro": "16 级 / Web Developer",
"url": "https://github.com/Last-Order"
},
{
"id": "fantasyqt",
"intro": "16 级 / 可能会运维 / 摸鱼选手",
"url": "http://0x2f.xyz"
},
{
"id": "vvv_347",
"intro": "16 级 / Rev / Windows / Freelancer",
"url": "https://vvv-347.space"
},
{
"id": "veritas501",
"intro": "16 级 / Bin / 被迫研狗",
"url": "https://veritas501.space"
},
{
"id": "LuckyCat",
"intro": "16 级 / Web 🐱 / 现于长亭科技实习",
"url": "https://jianshu.com/u/ad5c1e097b84"
},
{
"id": "Ash",
"intro": "16 级 / Java 开发攻城狮 / 996 选手 / 濒临猝死",
"url": "#"
},
{
"id": "Cyris",
"intro": "16 级 / Web 前端 / 美工 / 阿里云搬砖",
"url": "https://cyris.moe/"
},
{
"id": "Acaleph",
"intro": "16 级 / Web 前端 / 水母一小只 / 程序员鼓励师 / Cy 来组饥荒！",
"url": "#"
},
{
"id": "b0lv42",
"intro": "16级 / 大果子 / 毕业1年仍在寻找vidar娘接盘侠",
"url": "https://b0lv42.github.io/"
},
{
"id": "ngc7293",
"intro": "16 级 / 蟒蛇饲养员 / 高数小王子",
"url": "https://ngc7292.github.io/"
},
{
"id": "ckj123",
"intro": "16 级 / Web / 菜鸡第一人",
"url": "https://www.ckj123.com"
},
{
"id": "cru5h",
"intro": "16级 / 前web手、现pwn手 / 菜鸡研究生 / scu",
"url": "#"
},
{
"id": "xiaoyao52110",
"intro": "16 级 / Bin 打杂 / 他们说菜都是假的，我是真的",
"url": "#"
},
{
"id": "Undefinedv",
"intro": "15 级网安协会会长 / Web 安全",
"url": "#"
},
{
"id": "Spine",
"intro": "逆向 / 二进制安全",
"url": "#"
},
{
"id": "Tata",
"intro": "二进制 CGC 入门水准 / 半吊子爬虫与反爬虫",
"url": "#"
},
{
"id": "Airbasic",
"intro": "Web 安全 / 长亭科技安服部门 / TSRC 2015 年年度英雄榜第八、2016 年年度英雄榜第十三",
"url": "#"
},
{
"id": "jibo",
"intro": "15 级 / 什么都不会的开发 / 打什么都菜",
"url": "#"
},
{
"id": "Processor",
"intro": "15 级 Vidar 会长 / 送分型逆向选手 / 13 段剑纯 / 差点没毕业 / 阿斯巴甜有点甜",
"url": "https://processor.pub/"
},
{
"id": "HeartSky",
"intro": "15 级 / 挖不到洞 / 打不动 CTF / 内网渗透不了 / 工具写不出",
"url": "http://heartsky.info"
},
{
"id": "Minygd",
"intro": "15 级 / 删库跑路熟练工 / 没事儿拍个照 / 企鹅",
"url": "#"
},
{
"id": "Yotubird",
"intro": "15 级 / 已入 Python 神教",
"url": "#"
},
{
"id": "c014",
"intro": "15 级 / Web 🐶 / 汪汪汪",
"url": "#"
},
{
"id": "Explorer",
"intro": "14 级 HDUISA 会长 / 二进制安全 / 曾被 NULL、TD、蓝莲花等拉去凑人数 / 差点没毕业 / 长亭安研",
"url": "#"
},
{
"id": "Aklis",
"intro": "14 级 HDUISA 副会长 / 二次元 / 拼多多安全工程师",
"url": "#"
},
{
"id": "Sysorem",
"intro": "14 级网安协会会长 / HDUISA 成员 / Web 安全 / Freebuf 安全社区特约作者 / FSI2015Freebuf 特邀嘉宾",
"url": "#"
},
{
"id": "Hcamael",
"intro": "13 级 / 知道创宇 404 安全研究员 / 现在 Nu1L 划划水 / IoT、Web、二进制漏洞，密码学，区块链都看得懂一点，但啥也不会",
"url": "#"
},
{
"id": "LoRexxar",
"intro": "14 级 / Web 🐶 / 杭电江流儿 / 自走棋主教守门员",
"url": "https://lorexxar.cn/"
},
{
"id": "A1ex",
"intro": "14 级网安协会副会长 / Web 安全",
"url": "#"
},
{
"id": "Ahlaman",
"intro": "14 级网安协会副会长 / 无线安全",
"url": "#"
},
{
"id": "lightless",
"intro": "Web 安全 / 安全工程师 / 半吊子开发 / 半吊子安全研究",
"url": "https://lightless.me/"
},
{
"id": "Edward_L",
"intro": "13 级 HDUISA 会长 / Web 安全 / 华为安全部门 / 二进制安全，fuzz，符号执行方向研究",
"url": "#"
},
{
"id": "逆风",
"intro": "13 级菜鸡 / 大数据打杂",
"url": "https://github.com/deadwind4"
},
{
"id": "陈斩仙",
"intro": "什么都不会 / 咸鱼研究生 / <del>安恒</del>、<del>长亭</del> / SJTU",
"url": "https://mxgcccc4.github.io/"
},
{
"id": "Eric",
"intro": "渗透 / 人工智能 / 北师大博士在读",
"url": "https://3riccc.github.io"
}
]
'''
d = json.loads(j_data)
#在字典中寻找正确id
def finddict(s):
    for i in range(100):
        if d[i]["intro"] == s:
            print("success")
            print(d[i]["id"])
            return d[i]["id"]

s = requests.Session()
for i in range(102):
    url = "http://node2.anna.nssctf.cn:28420/api/getQuestion"
    page_text = s.get(url).text
    
    jspg = json.loads(page_text)
    intro = jspg["message"]
    print("intro:", intro)
    getid = finddict(intro)
    res2 = s.get("http://node2.anna.nssctf.cn:28420/api/getScore")
    print(res2.text)

    data = {
        "id": getid
    }
    resp = s.post("http://node2.anna.nssctf.cn:28420/api/verifyAnswer", data=data)
    print(resp.text)