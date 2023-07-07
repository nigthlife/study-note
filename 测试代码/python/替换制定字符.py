
str = 'NSSCTF{7[]0[]b3[]1[]4[]fe-0[]5[]b1[]-4[]eb2[]-b8[]1[]9[]-3[]3[]f3[]3[]dd2[]3[]5[]6[]9[]}'

rule = "[]"

newStr = str.replace(rule, "")

print(newStr)