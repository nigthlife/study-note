def construct_reverse_string(input_string):
    reverse_string = ""
    for char in input_string:
        if char.islower():
            reverse_string += char.upper()
        elif char.isupper():
            reverse_string += char.lower()
        else:
            reverse_string += char
    return reverse_string


input_string = input("请输入原始字符串：")
reverse_string = construct_reverse_string(input_string)
print("取反后的字符串：", reverse_string)