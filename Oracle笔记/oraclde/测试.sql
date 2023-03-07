
创建表空间

create tablespace my_tablespace
	datefile C:MYTS.DBF'
	size 100M
	autoextend on next 32M maxsize unlimited
	logging
	extent management local
	segment space management auto;

	--简写
	create tablespace my_tablespace
		datefile C:F:\Users\Oracle\oradata\orcl\MYTS.DBF


--创建用户语法
	create User User
		identified by password
		[default tablespace tablespace]
		[temporary tablespace tablespace]

--实例
	create User wsg
		identified by 密码
		default tablespace 表名

