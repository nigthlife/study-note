matrix = [0]*10
for j in range(len(matrix)):
    matrix[j] = input("请输入一个数字：")
print(matrix)
temp = matrix
for i in range(len(matrix)-1):
    for x in range(len(matrix)-i-1):
        if matrix[x] > matrix[x+1]:
            matrix[x], matrix[x+1] = matrix[x+1], matrix[x]


print(matrix)
