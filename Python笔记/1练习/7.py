Python 3.8.2 (tags/v3.8.2:7b3ab59, Feb 25 2020, 22:45:29) [MSC v.1916 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license()" for more information.
>>> "{0} love {1}.{2}.{3}".format("I","fishC","com")
Traceback (most recent call last):
  File "<pyshell#0>", line 1, in <module>
    "{0} love {1}.{2}.{3}".format("I","fishC","com")
IndexError: Replacement index 3 out of range for positional args tuple
>>> "{0} love {1}.{2}".format("I","fishC","com")
'I love fishC.com'
>>> "{a} love {b}.{c}".format(a="I",b="fishC",c="com")