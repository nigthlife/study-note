import base64


# base64多次解码
def base64_decode_multiple_times(encoded_str):
    decoded_str = encoded_str
    num_times = 0
    while True:
        try:
            decoded_bytes = base64.b64decode(decoded_str)
            decoded_str = decoded_bytes.decode('utf-8')
            num_times += 1

            # 在解码过程中捕获到 UnicodeDecodeError 异常，表示解码失败，此时跳出循环
        except UnicodeDecodeError:
            break

    return decoded_str, num_times



if __name__ == '__main__':
    # 测试
    encoded_str = "SGVsbG8gV29ybGQ="  # 要解码的Base64字符串

    decoded_str, num_times = base64_decode_multiple_times(encoded_str)
    print(f"解码结果：{decoded_str}")
    print(f"解码次数：{num_times}")

    # f = open('./TempFile/flag.txt', 'r').read()
    # decode(f)
