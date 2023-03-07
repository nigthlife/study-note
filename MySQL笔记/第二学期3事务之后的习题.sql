
















-- 随堂练习
-- 1、创建一个事件，在当前数据库下，
-- 在5分钟后创建一个tb_dept表，包含字段deptno,date
CREATE EVENT IF NOT EXISTS event_e  ON SCHEDULE
AT NOW() + INTERVAL 5 MINUTE
DO
CREATE TABLE tb_dept(deptno DATE);


-- 2、从2019-5-19起每分钟定时清空表tb_test中内容:
CREATE EVENT IF NOT EXISTS e_clear ON SCHEDULE
EVERY 1 MINUTE 
STARTS TIMESTAMP '2019-5-19 15:00:00'
DO TRUNCATE TABLE tb_test;


-- 3、每2分钟定时清空表，5分钟后停止执行:
CREATE EVENT IF NOT EXISTS e_cle ON SCHEDULE
EVERY 2 MINUTE 
ENDS CURRENT_TIMESTAMP + INTERVAL 5 MINUTE
DO TRUNCATE TABLE tb_test;


-- 4、2分后开启每分钟定时清空表，6分钟停止执行
CREATE EVENT IF NOT EXISTS e_c  ON SCHEDULE
EVERY 1 MINUTE
STARTS CURRENT_TIMESTAMP + INTERVAL 2 MINUTE
ENDS CURRENT_TIMESTAMP + INTERVAL 6 MINUTE
DO TRUNCATE TABLE tb_test;


-- 5、创建一个事件从现在开始到2分钟后结束，每隔5s往test表中插入数据
CREATE EVENT IF NOT EXISTS e_mi ON SCHEDULE
EVERY 2 SECOND 
ENDS CURRENT_TIMESTAMP + INTERVAL 2 MINUTE
DO INSERT INTO test VALUES(NOW());


-- 6、创建一个一分钟后清空test数据表中的数据
CREATE EVENT event_delect ON SCHEDULE
AT NOW() + INTERVAL 1 MINUTE
DO DELETE FROM test;




ALTER EVENT e_mi DISABLE
ALTER EVENT event_delect DISABLE
ALTER EVENT e_c DISABLE
ALTER EVENT e_cle DISABLE
ALTER EVENT e_clear DISABLE
ALTER EVENT event_e DISABLE



-- 实训报告16










-- (1)在数据库db_school中创建一个立即执行的事件，
-- 创建一个student表包括字段sname，sno,birthday,sex
CREATE EVENT event_create ON SCHEDULE
AT NOW() DO
CREATE TABLE student(sname VARCHAR(20),sno
INT,birthday DATE,sex CHAR(3));

-- (2)在数据库db_school中创建一个立即执行的事件，
-- 10秒后创建一个表class包括字段cname，cno;
CREATE EVENT event_create1 ON SCHEDULE
AT NOW() + INTERVAL 10 SECOND  DO 
CREATE TABLE class(cname VARCHAR(20),cno INT);

-- (3)数据库db_school中创建一个事件，每60秒插入一条记录到student表；
CREATE EVENT event_insert ON SCHEDULE
EVERY 1 MINUTE DO
INSERT INTO student VALUES(NOW());
`student`

-- (4)数据库db_school中创建一个事件，
-- 从现在开始到5分钟之后结束，每10秒插入一条记录到student表；
CREATE EVENT IF NOT EXISTS event_insert1 ON SCHEDULE
EVERY 10 SECOND
ENDS CURRENT_TIMESTAMP + INTERVAL 5 MINUTE
DO INSERT INTO student(birthday) VALUES(NOW());
TRUNCATE
-- (5)在数据库db_school中创建一个事件，每天定时清空student表数据;
CREATE EVENT event_del ON SCHEDULE
EVERY 1 DAY  DO
DELETE FROM student ;


-- (6)在数据库db_school中创建一个事件，从下一个月开始，
-- 每个月都清空一次student表，并且在2020年的12月31日22时结束;
CREATE EVENT event_month ON SCHEDULE
EVERY 1 MONTH
STARTS CURRENT_TIMESTAMP + INTERVAL 1 MONTH
ENDS '2020-12-31 22:00:00' DO 
TRUNCATE TABLE student;


-- (7)在数据库db_school中将每天清空student表改为1周清空一次；
ALTER EVENT event_del ON SCHEDULE
EVERY 7 DAY DO 
DELETE FROM student;

-- (8)查看所有创建的事件；
SHOW EVENTS;


-- (9)删除事件event_delete；
DROP EVENT event_delete;



-- 随堂练习-17

ALTER EVENT IF NOT EXISTS  event_create ON SCHEDULE
AT NOW() + INTERVAL 1 MINUTE
DO
CREATE TABLE test_event(stuname CHAR(10),birthday DATE);

SHOW TABLES
SHOW EVENTS

CREATE EVENT IF NOT EXISTS event_insert ON SCHEDULE
EVERY 10 SECOND
STARTS NOW()
ENDS NOW() + INTERVAL 5 MINUTE
DO INSERT INTO test_create VALUES(NULL,NULL);

SELECT * FROM test_event



-- 十八周练习
-- 1、创建事件v1,要求在1分钟后创建借阅表tb_borrow的备份表borr_backup;
SHOW CREATE TABLE tb_borrow
DESC tb_borrow
CREATE EVENT v1 ON SCHEDULE 
AT NOW()+ INTERVAL 1 MINUTE
DO 
CREATE TABLE boor_backup LIKE tb_borrow;-- 复制表结构




-- 2、创建事件v2，要求在每个月1日0点执行清空备份表borr_backup，
-- 再从借阅表批量添加数据到备份表的操作；
DELIMITER $$
CREATE EVENT IF NOT EXISTS v2 ON SCHEDULE
EVERY 1 MONTH
STARTS '2020-07-01' 
DO TRUNCATE TABLE borr_backup;
INSERT INTO boor_backup SELECT * FROM tb_borrow;
END$$ -- 复制表信息
DELIMITER ;


-- 3、临时关闭事件v2
ALTER EVENT v2 DISABLE;

-- 4、启用事件v2
ALTER EVENT v2 ENABLE;

-- 5、重命名事件v2为v_bf
ALTER EVENT v2 RENAME TO v_bf;

-- 1、创建视图v1,要求包含字段图书名称、类型编号、描述；
-- 这个视图允许更新吗？
CREATE OR REPLACE VIEW v1 AS 
SELECT bname,classNO `db_book`FROM tb_book JOIN tb_class ON tb_book.btype = tb_class.`classNo`;

-- 2、创建视图v2，要求包含字段图书名称、图书类型名称;这个视图允许更新吗？
CREATE OR REPLACE VIEW v2 AS
SELECT bname,className FROM tb_book JOIN tb_class ON tb_book.btype = tb_class.`classNo`;


-- 3.创建视图v3,要求包含字段图书名称、总金额（数量*单价）；这个视图允许更新吗
CREATE OR REPLACE VIEW v3 AS
SELECT bname,SUM(bnum * price) FROM tb_book GROUP BY bname;	

-- 4、查看视图的基本结构、详细结构；
DESC v3; -- 基本结构
SHOW CREATE VIEW v3;-- 详细结构

-- 5、修改视图v2，要求删除图书类型名称字段，添加字段出版社publisher;
CREATE OR REPLACE VIEW v2 AS
SELECT bname,publisher FROM tb_book;

-- 6、删除视图v1 v2 v3；
DROP VIEW v1,v2,v3;

-- 7、查询未被借出去的图书名称;(使用子查询)
SELECT bname FROM tb_book WHERE bname NOT IN(
SELECT bname FROM tb_borrow JOIN tb_book ON tb_borrow.`bookNo`=tb_book.`bno`)

-- 8、统计14年1月被借出的图书名称;(使用子查询)
SELECT bname FROM tb_book WHERE bname IN
(SELECT bname FROM tb_borrow JOIN tb_book ON tb_borrow.`bookNo`=tb_book.`bno`
WHERE borrowDate LIKE "2014-01%");

SELECT * FROM tb_book WHERE publisher='高等教育出版社' -- 
  UNION 
  SELECT * FROM tb_book WHERE publisher='武汉出版社' LIMIT 3 OFFSET 0  ;

-- 10.查询借阅者姓名、学院名称、是否延期(isDelay)，如延期设置字段isdelay
-- 值为‘延期’，未延期设置为空字符串；
SELECT readername,department,IF(shouldDate < returnDate,"延期","未延期") AS isDelay
FROM tb_reader JOIN tb_borrow ON tb_reader.readerNo= tb_borrow.readerNO;

-- 11、统计图书被出借的次数，要求显示图书名称及出借次数；
SELECT bname,COUNT(bookNO) FROM tb_borrow JOIN tb_book ON tb_borrow.`bookNo`=tb_book.`bno`
GROUP BY bookno 

-- 12、统计图书被出借的次数，要求显示出借次数排名前三的图书名称及出借次数；
SELECT bname,COUNT(bookNO) FROM tb_borrow JOIN tb_book ON tb_borrow.`bookNo`=tb_book.`bno`
GROUP BY bookno ORDER BY bookno ASC LIMIT 0,3

-- 13、统计“MySQL程序设计”、“PHP程序设计”被出借的次数，
-- 要求显示图书名称及出借次数；
SELECT bname,COUNT(bookno) FROM tb_borrow JOIN tb_book ON tb_borrow.`bookNo`=tb_book.`bno`
GROUP BY bookno HAVING bname = "MySQL程序设计" OR bname = "PHP程序设计"


-- 14、查询刘志明的借阅记录；
SELECT * FROM tb_borrow WHERE readerNo IN
(SELECT readerNo FROM tb_reader WHERE readerName = '刘志明')

-- 15、查询和周敏年龄相同的学生信息（使用自连接）
SELECT b.* FROM tb_reader a,tb_reader b WHERE a.age=b.age
AND a.readername = '周敏' AND b.readername != '周敏'


-- 16、查询和“新华字典”出版社相同的图书信息（使用自连接）
SELECT  b.* FROM tb_book a,tb_book b WHERE a.publisher = b.publisher
AND a.bname = '新华字典'-- in(select publisher from tb_book where bname = '新华字典')
AND b.bname != '新华字典'

-- 17、使用左连接查询所有书籍的借阅情况，显示字段书名、借阅者编号、出借日期；
SELECT bname,readerno,borrowdate FROM
tb_book LEFT JOIN tb_borrow
ON bno = bookno;

-- 18、使用右连接查询所有书籍分类及对应书名，显示tb_class表中的所有字段及书名；
SELECT tb_class.*,bname FROM 
tb_book RIGHT JOIN tb_class
ON btype = classno

-- 19、表tb_book,查询高等教育出版社出版的图书名称、入库时间及数量；
SELECT bname,bdate,bnum FROM tb_book WHERE publisher = '高等教育出版社'

-- 20、表tb_book,查询教材类用书信息并按入库时间倒序排列；
SELECT * FROM tb_book WHERE desc1 LIKE '%教材' ORDER BY bdate ASC


-- 21、表tb_reader, 查询各学院读者的平均年龄、最大年龄及最小年龄；
SELECT department,AVG(age),MAX(age),MIN(age) FROM tb_reader GROUP BY department;

-- 22、表tb_reader, 查询各学院男、女生人数；
SELECT department,sex,COUNT(sex)FROM tb_reader WHERE sex='男'GROUP BY department 
UNION 
SELECT department,sex,COUNT(sex)FROM tb_reader WHERE sex= '女'GROUP BY department 


-- 24、读者表tb_reader与图书表tb_book做笛卡尔积连接，
-- 要求显示字段读者姓名readername和书名bname;
SELECT readername,bname FROM tb_borrow a INNER JOIN tb_reader b CROSS JOIN tb_book c ON 
a.readerNo = b.readerNo AND a.bookNo = c.bno




-- 第十九次课 触发器
CREATE s BEFORE INSERT ON tb_class FOR EACH ROW 

SHOW TRIGGERS;

CREATE TRIGGER SumOfSalary BEFORE INSERT ON tb_emp8 FOR EACH ROW
SET @sum=@sum+New.salary

CREATE TRIGGER s BEFORE INSERT ON tb_emp8 FOR EACH ROW FOR EACH EACH ROW
EACH  BEFORE BEFORE BEFORE BEFORE BEFORE 

CREATE TRIGGER double_salary AFTER INSERT ON 表名
FOR EACH ROW INSERT INTO 表名2 
VALUES(new.id,new.name,deptId,2*new.salary)


CREATE TABLE myevent(id INT(11)DEFAULT NULL,
		     evtname CHAR(20)DEFAULT NULL);
CREATE TABLE account(accnum INT(4),
		     amount DECIMAL(10,2)); 
-- 创建一个名为 trigupdate 的触发器，每次 account 表更新数据之后都向 
-- myevent 数据表中插入一条数据。
CREATE TRIGGER trigupdate AFTER UPDATE ON account FOR
EACH ROW INSERT INTO myevent VALUES(1,'after update');

SELECT * FROM information_schema.triggers WHERE trigger_name ='trigupdate'



-- 练习十三（连接查询与子查询）
-- 1.对morder表的数据，查询订单金额大于500，每个区域的订单总金额；
SELECT region,SUM(order_price) FROM morder GROUP BY region HAVING SUM(order_price)>500


-- 2.对morder表的数据，按照区域和类型进行分组，查询出总金额大于5000，每个区域和类型订单的总金额；
SELECT region,`type`,SUM(order_price) FROM morder GROUP BY region,`type` HAVING 
SUM(order_price)>5000


-- 3.查找北京区域订单的用户名和手机号;
SELECT user_name,phone_num FROM morder,`user` WHERE morder.user_id = `user`.id 
AND region = '北京'

-- 4.查询从来没有下过单的用户名称；
SELECT user_name FROM `user` WHERE id NOT IN(SELECT user_id FROM morder)


-- 5.查询订单金额低于平均订单金额的订单价格以及所属用户名；
SELECT order_price,user_name FROM morder,`user` WHERE  
 morder.user_id = `user`.id  AND order_price <(SELECT AVG(order_price)FROM morder)


-- 6.查询user表中重复的email地址；
SELECT email FROM `user` GROUP BY email HAVING  COUNT(*)>1



-- 7.统计订单金额大于平均金额的每个地区订单总金额，按照倒序排列，取总金额最高的第2个地区；
SELECT region,SUM(order_price) FROM morder WHERE order_price >
(SELECT AVG(order_price) FROM morder) GROUP BY region 
ORDER BY order_price ASC LIMIT 0,2;


-- 8.查询北河年龄相同的订单信息；
SELECT morder.* FROM morder INNER JOIN USER 
WHERE morder.user_id = user_id AND user_id IN
(SELECT id FROM USER WHERE age IN
(SELECT age FROM USER WHERE user_name = '北河'))



#### -- 第十九周 触发器

```sql
CREATE TRIGGER ins_trigger 
AFTER INSERT ON tb_student
FOR EACH ROW  SET @srt=' one student added'
DROP TRIGGER in_trigger

CREATE TRIGGER in_trigger
AFTER INSERT ON tb_student
FOR EACH ROW 
SET @str = new.studentName;


INSERT INTO tb_student VALUES
('2013110101','张小英','男','1997-12-11','闪现','汉','AC3434')


SELECT * FROM tb_student

DELIMITER $$
CREATE TRIGGER t4
AFTER INSERT ON tb_student
FOR EACH ROW BEGIN
IF new.sex IS NULL THEN SET new.sex = '女';
ELSE SET new.sex = '男';
END IF;
END $$
DELIMITER ;

DELIMITER $$
CREATE TRIGGER tir_update
AFTER UPDATE ON tb_student
FOR EACH ROW
BEGIN
INSERT INTO LOG VALUES(USER(),'update',old.studentno,
old.studentname,'修改前',NEW());
INSERT INTO LOG VALUES(USER(),'update',new.studentno,
new.studentname,'修改前',NEW());
```





-- insert插入类型

-- 在insert触发器代码内引用一个名为new的虚拟表来访问被插入的行
-- 在before insert触发器中，new中的值也可以被更新，允许更改被插入的值
-- 对auto_increment列，new在insert执行之前是0值
-- 在insert执行之后将包含新的自动生成值
CREATE TRIGGER in_trigger
AFTER INSERT ON tb_student 
FOR EACH ROW SET @str = new.studentno;

INSERT INTO tb_student VALUES('2013110101','张小银',
'男','1997-12-11','山西','汉','AC1301');

SELECT @str;


-- update更新类型

-- update触发器代码内引用

-- 1.在update触发器代码内引用一个名为old的虚拟表来访问以前的值，
-- 也可以引用一个new的虚拟表访问更新的值

-- 2.在before update触发器中，new中的值可能也被更新，
-- 允许更改将要用于update语句中的值

-- 3.old中的值全部是只读的，不能被更相信
-- 4.当触发器涉及对表自身的更新操作，只能用before update
-- 而after触发器将不被允许

```sql
CREATE TRIGGER up_trigger
BEFORE UPDATE ON tb_student 
FOR EACH ROW SET new.nation = old.native;
UPDATE tb_student SET nation = '壮' WHERE 
studentname = '张晓喑';
```



-- delete触发器


-- 在delete触发器代码内引用一个名为old的虚拟表来访问被删除的行
-- old中的值全部是只读，不能被更新

-- 十七周
-- (1)在数据库db_school的表tb_student中创建一个触发器
-- tr_tb_student_insert，用于每次向表tb_student
-- 中插入一行数据时，将学生变量str的值设置为
-- 'one student added';

```sql
DROP TRIGGER`in_trigger`
CREATE TRIGGER tr_tb_student_insert 
AFTER INSERT ON tb_student 
FOR EACH ROW SET @str = 'one student added';

INSERT INTO tb_student VALUES('201311002','哈','男','1995-02-06',
			      '山东','汉','AE1566');
SELECT @str
```





-- (2)在数据库db_school的表tb_student中创建触发器
-- tr_tb_student_insert，用于每次向表tb_student
-- 中插入一行数据时，
-- 将学生变量str的值设置为新插入的学生的学号。

```sql
DROP TRIGGER tr_tb_student_insert
CREATE TRIGGER tr_tb_student_insert
AFTER INSERT ON tb_student
FOR EACH ROW SET @str = new.studentno;
INSERT INTO tb_student VALUES('201311772','哈','男','1995-02-06',
			      '山东','汉','AE1566');
SELECT @str
DROP  TRIGGER tr_tb_student_insert
```

-- (3)创建一个触发器tr_tb_student_delete，用于从
-- student表中删除数据时,查看被删除的学生的学号和名称；;

```sql
DELIMITER !!
CREATE TRIGGER tr_tb_student_delete
BEFORE DELETE ON student 
FOR EACH ROW BEGIN
SET @str_1=old.studentno;
SET @str_2=old.studentname;
END;
DELIMITER ;
DROP  TRIGGER tr_tb_student_delete
```

-- (4)当向tb_student表中插入数据时，如果输入的
-- 民族不是'汉'，则将该列设置为'少数名族'；;

```sql
DELIMITER !!
CREATE TRIGGER in_trigger
BEFORE INSERT ON tb_student
FOR EACH ROW BEGIN
IF new.nation !='汉' THEN
SET new.nation = '少数名族';
END IF;
END !!
```



-- (5)在数据库db_score的表tb_score中创建一个触发器
-- tr_tb_score_update,用于每次更新表tb_score时，将该表中score列的值在原值基础上加1；;

```sql
CREATE TRIGGER tr_tb_score_update
AFTER UPDATE ON tb_score
FOR EACH ROW 
UPDATE tb_score SET new.score =(new.score +1);


UPDATE tb_score SET courseno='31001' WHERE studentno= '2013110101';

DROP  TRIGGER tr_tb_score_update
```



-- (6)创建触发器tri_tb_score_insert,用于校验分数score只能在0-100之间，
-- 小于0时，将分数置为0，大于100时，将分数置为100；
CREATE TRIGGER tri_tb_score_insert
BEFORE UPDATE ON tb_score
FOR EACH ROW






-- (7)创建一个触发器tr_tb_class_insert，用于每次向tb_student表中插入
-- 一条数据时，tb_class表中的班级人数(num)的值加1；

-- (8)查看所有创建的触发器；

-- (9)删除触发器t_insert_trigger；

#### (1)在数据库db_school的表tb_student中创建一个触发器tr_tb_student_insert，用于每次向表tb_student中插入一行数据时，将学生变量str的值设置为'one student added';

CREATE TRIGGER tr_tb_student_insert
AFTER INSERT ON tb_student
FOR EACH ROW 
SET @str='one student added';
DROP TRIGGER tr_tb_student_insert

#### (2)在数据库db_school的表tb_student中创建触发器tr_tb_student_insert，用于每次向表tb_student中插入一行数据时，将学生变量str的值设置为新插入的学生的学号。#

CREATE TRIGGER tr_tb_student_insert
AFTER INSERT ON tb_student
FOR EACH ROW 
SET @str=new.`studentNo`;
DROP TRIGGER tr_tb_student_insert

#### (3)创建一个触发器tr_tb_student_delete，用于从student表中删除数据时，

查看被删除的学生的学号和名称；;

DELIMITER $$
CREATE TRIGGER tr_tb_student_delete
BEFORE DELETE ON `tb_student`
FOR EACH ROW 
BEGIN
SET @a=old.`studentNo`;
SET @b=old.`studentName`;	
END$$
DROP TRIGGER tr_tb_student_delete;

##### (4)当向tb_student表中插入数据时，如果输入的民族不是'汉'，则将该列设置为'少数名族'；;

DELIMITER $$
CREATE TRIGGER tb_student_insert
BEFORE INSERT ON tb_student
FOR EACH ROW 
BEGIN
IF new.nation!='汉' THEN
SET new.nation='少数名族';
END IF;
END$$

INSERT INTO tb_student(nation) VALUES (888);
DELIMITER ;
DROP TRIGGER tb_student_insert

#### (5)在数据库db_score的表tb_score中创建一个触发器tr_tb_score_update,

用于每次更新表tb_score时，将该表中score列的值在原值基础上加1；;

CREATE TRIGGER tr_tb_score_update
BEFORE UPDATE ON tb_score
FOR EACH ROW
SET new.score = old.`score`+1

#####(6)创建触发器tri_tb_score_insert,用于校验分数score只能在0-100之间，

####小于0时，将分数置为0，大于100时，将分数置为100；

DELIMITER $$
CREATE TRIGGER tri_tb_score_insert
BEFORE INSERT ON tb_score
FOR EACH ROW
BEGIN
IF new.score>100 THEN
SET new.score=100;
ELSE IF new.score <0 THEN
SET new.score=0;
END IF;
END IF;
END $$

DELIMITER ;
DROP TRIGGER tri_tb_score_insert;

####(7)创建一个触发器tr_tb_class_insert，用于每次向tb_student表中插入一条数据时，tb_class表中的班级人数(num)的值加1；

DROP TRIGGER ri_tb_score_insert
`db_school`
CREATE TRIGGER tr_tb_class_insert
BEFORE INSERT ON tb_student
FOR EACH ROW
UPDATE tb_class SET classnum=classnum+1;

####(8)查看所有创建的触发器；

SHOW TRIGGERS;

####(9)删除触发器t_insert_trigger；

DROP TRIGGER t_insert_trigger;



####十八周存储过程

查看存储过程
SHOW PROCEDURE STATUS





####(1)使用存储过程计算两个数的和

CREATE PROCEDURE pr_sum(INOUT su INT,INOUT sut INT)
SET @sum = su + sut;
SET @a = 10;
SET @b = 100;
CALL pr_sum(@a,@b);
SELECT @sum;


DELIMITER $$
CREATE PROCEDURE pr_sum1()
BEGIN
DECLARE a INT;
DECLARE b INT;
SET a = 10;
SET b = 20;
SET a = a +b;
SELECT a;
END$$
CALL pr_sum1()
####(2)创建一个存储过程，用于得到某个指定学生的籍贯

DELIMITER &&
CREATE PROCEDURE jiguan(IN stu INT(11))
BEGIN
DECLARE n CHAR(20);
SELECT native INTO n FROM tb_student WHERE studentno=stu;
SELECT n;
END
CALL jiguan(2013110101);



####(3)使用存储过程查询成绩为90的学生学号;

CREATE PROCEDURE inqir(IN number INT(11))
SELECT studentNo FROM tb_score WHERE score =number;

CALL inqir(90);

####(4)使用存储过程，用指定的学号作为参数来删除某一个学生记录；

CREATE PROCEDURE del(IN de INT(11))
DELETE FROM tb_student WHERE studentno=de;
CALL del(201311772)

####(5)使用存储过程，用指定的学号和课程号为参数查询学生成绩;

CREATE PROCEDURE chaxun(IN stu1 INT(11),IN cour INT(11))
SELECT DISTINCT score FROM tb_score WHERE studentno=stu1 AND courseno=cour;
CALL chaxun(2013110101,21001);

####(6)在存储过程中将tb_student表中的学号为

####2013110101的学生的‘管理学’的成绩的值赋给变量stu;

DELIMITER $$
CREATE PROCEDURE study(IN a INT(11))
BEGIN
DECLARE cour CHAR(20);
SELECT courseno INTO cour FROM tb_course WHERE coursename='管理学';
SELECT cour;
SELECT DISTINCT score INTO @stu FROM tb_score WHERE courseno = cour AND studentno=a;
END
CALL study(2013110101)
SELECT @stu

SELECT score FROM tb_score WHERE courseno = 11003 AND studentno=2013110101

####(7)在jxgl数据库中，创建一个存储过程，有两个输入参数分别为：

####xh和kch，分别代表学号和课程号，如果的学生成绩大于等于60分时，

####将该课程的学分累加计入到该生的总学分，否则，总学分不变；

DELIMITER $$
CREATE PROCEDURE dis(IN xh INT(11),IN kch CHAR(20))
BEGIN
DECLARE sc INT;	-- 插入数据的分
DECLARE sum1 INT;-- 未插入数据的总分
SELECT credit FROM credit WHERE s_no=xh;
SELECT report INTO sum1 FROM score WHERE s_no=xh AND c_no=kch;#求出成绩
SELECT  credit INTO sc FROM course WHERE c_no=kch;#求出这个课程的学分
IF sum1 >=60 THEN#判断成绩是否大于60
UPDATE credit SET credit=credit+sc;#大于就更新数据
SELECT credit FROM credit WHERE s_no=xh;
END IF;
END

CALL dis(122001,'A001')



####(8)查看某一个存储过程；

SHOW CREATE PROCEDURE dis

####(9)删除存储过程sp_sum；

DROP PROCEDURE sp_sum



-- 练习

```mysql
SELECT report INTO sum1 FROM score WHERE s_no=
IF report >=60 THEN
SET suml+=crdit



CREATE PROCEDURE del(IN sno INT(11))
DELETE FROM tb_score WHERE studentno=sno;

CREATE PROCEDURE del(IN nam CHAR(10))
BEGIN
DECLARE stu;
SELECT srud entno INTO stu FROM tb_student WHERE 
studentname=nam;
DELETE FROM tb_score WHERE studentno=stu;
END


CREATE PROCEDURE sc(IN cour INT(11),IN shu DOUBLE)
SELECT AVG(score) INTO shu FROM tb_score 
WHERE courseno=cour



CREATE PROCEDURE p3
BEGIN
DECLARE su INT;
SELECT COUNT(*) INTO su FROM tb_score 


DELIMITER $$
CREATE PROCEDURE proc7(OUT st INT)
BEGIN
SELECT COUNT(*) INTO st FROM tb_student;
SELECT st;
END$$

CALL proc7(@st);
INSERT  INTO `goods`(`goods_id`,`good_name`,`unitprice`,`provider`) VALUES (1,'乐事黄瓜味','5.80','lote'),(2,'康师傅红烧牛肉面','5.50','康师傅'),(3,'乐事西红柿味薯片','5.80','lote');


CREATE TABLE `goods` (
  `goods_id` INT(11) NOT NULL AUTO_INCREMENT,
  `good_name` VARCHAR(20) NOT NULL,
  `unitprice` DECIMAL(10,2) DEFAULT NULL,
  `provider` VARCHAR(50) DEFAULT NULL,
  PRIMARY KEY (`goods_id`)
) ENGINE=INNODB AUTO_INCREMENT=4 DEFAULT CHARSET=gb2312

-- 二十一周
CREATE TABLE customer(
customer_id INT(11)NOT NULL PRIMARY KEY,
`name` CHAR(20) NOT NULL ,
address VARCHAR(30)DEFAULT 'nc',
email VARCHAR(30)UNIQUE);


CREATE TABLE goods(
goods_id INT(11)NOT NULL AUTO_INCREMENT PRIMARY KEY,
good_name VARCHAR(20)NOT NULL,
unitpric DECIMAL(10,2),
provider VARCHAR(50));

CREATE TABLE purchase(
order_id VARCHAR(20)NOT NULL PRIMARY KEY,
customer_id INT(10),
goods_id INT(10),
nums intt(11)NOT NULL,
CONSTRAINT fk_cu FOREIGN KEY(customer_id)
REFERENCES customer(customer_id),
CONSTRAINT fk_good FOREIGN KEY(goods_id )
REFERENCES goods(goods_id));
```



#####2、向商品表goods添加2行数据(同时)

INSERT INTO goods(good_name,unitprice,provider)
VALUES('乐事黄瓜味','5.80','lote'),
      ('康师傅红烧牛肉面','5.50','康师傅');

#####3、向客户表customer添加1行数据

INSERT INTO customer(customer_id,`name`)
VALUES (1001,'宋小宝');

#####4、更新customer表，

#####设置姓名为“小李”的客户地址为“铁岭”，

#####邮件地址为“10086@qq.com”

UPDATE customer SET address = '铁岭'
,email = '10086@qq.com'WHERE `name`='小李'

#####5、表customer，在字段name上添加唯一索引id_name

ALTER TABLE customer ADD UNIQUE INDEX id_name2(`name`);
CREATE UNIQUE INDEX id_name ON customer(NAME)

#####6、查询goods表价格在500~600之间的物品信息

SELECT * FROM goods WHERE unitprice BETWEEN 500 AND 600

#####7、查询物品名称中含有“牛肉”字样的物品名称及价格

SELECT good_name,unitprice FROM goods WHERE good_name
LIKE '%牛肉%';

#####8、商品表中,删除所有编号为空的记录

DELETE FROM goods WHERE goods_id IS NULL

#####9、写出客户表customer与商品表goods做交叉连接的SQL语句

#####；若customer表中有5行数据，

#####goods表中有10 行数据，交叉连接后产生的结果集有几行？

SELECT * FROM customer CROSS JOIN goods 

#####10、查询乐事商品订单数

SELECT COUNT(*) FROM purchase WHERE goods_id IN(SELECT goods_id
FROM goods WHERE good_name LIKE '%乐事%')

#####11、查询客户“lisa”的订单信息

SELECT * FROM purchase WHERE customer_id IN(
SELECT customer_id FROM customer WHERE `name`='lisa');

#####12、创建视图v_p, 显示出售商品总数，

#####要求包含字段商品编号、出售总数；该视图可以被更新吗？

CREATE VIEW v_p AS SELECT SUM(nums) 销售总数,goods_id FROM
purchase GROUP BY goods_id

#####13、创建视图v_sell,显示已被出售的商品编号;该视图可以被更新吗？

CREATE VIEW v_sell AS 
SELECT DISTINCT goods_id FROM purchase WHERE nums IS NOT NULL

#####14、创建事件v_del，用于每周日23：59：59

#####删除purchase表中nums为0的数据

CREATE EVENT v_del ON SCHEDULE 
EVERY 7 DAY
STARTS TIMESTAMP '2020.6.28 23:59:59'
DO DELETE FROM purchase WHERE nums=0;

#####15、创建事件v_cre,

#####用于5分钟后创建表customer的备份表cust_bk,

#####要求复制表结构与数据；

CREATE EVENT v_cre ON SCHEDULE
AT NOW()+ INTERVAL 5 MINUTE DO
CREATE TABLE cust_bk SELECT * FROM customer;

#####17、创建触发器tri2，

#####用于删除customer表的客户信息后

#####同步删除purchase表中该客户的相关交易记录;

##### CREATE TRIGGER tri2 

AFTER DELETE ON customer
FOR EACH ROW 
DELETE FROM purchase WHERE customer_id=customer.old.customer_id


DELETE FROM customer WHERE customer_id=1



-- 二十二复习
CREATE TABLE class
(classno INT PRIMARY KEY
);

CREATE TABLE Tb_student(
sno INT PRIMARY KEY AUTO_INCREMENT,
sname CHAR(10) UNIQUE,
birthday DATE NOT NULL UNIQUE,
tel CHAR(20),
ssex VARCHAR(2) NOT NULL,
nation VARCHAR(10)DEFAULT'汉',
classno INT,
INDEX index_sex(ssex,nation),
UNIQUE INDEX c(tel),
FOREIGN KEY(classno) REFERENCES class(classno)
);

ALTER TABLE tb_student DROP sno;

ALTER TABLE tb_student ADD  sno INT PRIMARY KEY AUTO_INCREMENT;

ALTER TABLE tb_student DROP INDEX sname;
DROP INDEX sname ON Tb_student;

ALTER TABLE tb_student ADD UNIQUE INDEX a(sname);

ALTER TABLE tb_student MODIFY sname CHAR(10)NOT NULL;

ALTER TABLE tb_student ADD native CHAR(10)UNIQUE 

ALTER TABLE tb_student MODIFY nation VARCHAR(10)DEFAULT '少数名族'

ALTER TABLE tb_student DROP nation;
ALTER TABLE tb_student ADD nation VARCHAR(10)DEFAULT '少数名族';

ALTER TABLE tb_student CHANGE ssex sex VARCHAR(10);

ALTER TABLE tb_student ADD INDEX index_a(nation,native);

ALTER TABLE tb_student DROP FOREIGN KEY tb_student_ibfk_1;

ALTER TABLE tb_student ADD CONSTRAINT h 
FOREIGN KEY(classno) REFERENCES class(classno)

CREATE TABLE en1(
eno INT,
ename CHAR(10),
eclass INT,
enum1 INT
);
ALTER TABLE en1 ADD UNIQUE INDEX q_en(eno);
ALTER TABLE en1 ADD FULLTEXT INDEX q_e(ename);
ALTER TABLE en1 ADD INDEX q_s(ename,eclass);
ALTER TABLE enq ADD INDEX q_g(num1);
CREATE INDEX q_g ON en1(num1);




-- 第二十三周
CREATE TRIGGER tei2 AFTER DELETE ON customer
FOR EACH ROW 
DELETE FROM pur WHERE old.=old.