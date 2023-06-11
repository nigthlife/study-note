import base64

# 将 Base64 编码的字符串解码为字节串
bytes_str = base64.b64decode(b'sRxNyxI1BPqvJSx5KAuMxMQFnuCfJSlHVhbx855a')

# 将字节串按照 UTF-8 编码格式解码为 Unicode 字符串
unicode_str = bytes_str.decode('utf-8')

# 将 Unicode 字符串按照 ASCII 编码格式转换为 ASCII 码
ascii_str = unicode_str.encode('ascii', 'ignore')

# 输出结果
print(ascii_str)