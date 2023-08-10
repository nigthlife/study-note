
# 八进制转十进制
def octal_to_decimal(octal_str):
    try:
        decimal_num = int(octal_str, 8)
        return decimal_num
    except ValueError:
        return None

def decimal_to_ascii(decimal_num):
    try:
        ascii_char = chr(decimal_num)
        return ascii_char
    except ValueError:
        return None

if __name__ == '__main__':

    # 测试
    octal_str = "1234"  # 要转换的八进制数

    decimal_num = octal_to_decimal(octal_str)

    if decimal_num is not None:
        print(f"十进制结果：{decimal_num}")
        str = decimal_to_ascii(decimal_num)
    else:
        print("转换失败，请确认输入的八进制数是否正确。")