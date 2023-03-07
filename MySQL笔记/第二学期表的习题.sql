CREATE DATABASE Library;
CREATE TABLE UserType(
ID INT PRIMARY KEY NOT NULL,
`Type` CHAR(10)	NOT NULL
);
INSERT INTO UserType VALUES(0,'超管'),
			   (1,'图书管理员'),
			   (2,'读者');
CREATE TABLE Login(
UserName CHAR(16) PRIMARY KEY,
UserPwd CHAR(16)NOT NULL,
userType INT NOT NULL,
CONSTRAINT Usertype_type FOREIGN KEY UserName REFERENCES 
);
DROP TABLE Books;
CREATE TABLE Books(
isbn CHAR(13)PRIMARY KEY,
BookName CHAR(16)NOT NULL,
BookAuthor CHAR(8),
category CHAR(8),
Price DOUBLE(10,2)NOT NULL,
`Status` INT NOT NULL,
BookDay DATE
);
CREATE TABLE Reader(
readerid INT AUTO_INCREMENT PRIMARY KEY,
`name` CHAR(16)NOT NULL,
sex CHAR(2),
address CHAR(50),
phone CHAR(11)NOT NULL,
`status` INT(8)NOT NULL
);
CREATE TABLE BorrowReturn(
bor_ret_id INT AUTO_INCREMENT PRIMARY KEY,
`sibn` CHAR(13)NOT NULL,
readerid INT NOT NULL,
borrowdate DATE NOT NULL,
retdatep DATE NOT NULL,
retdatea DATE,
isdelay INT NOT NULL
);
SHOW CREATE DATABASE db_school;
CREATE DATABASE IF NOT EXISTS db_s;
CHARACTER SET = 字符集;
COLLATE = 校队规则，
ALTER DATABASE 数据库名；
DEFAULT CHARACTER SET 字符集名称；
DEFAULT COLLATE 校队规则
DROP DATABASE db_s;
CREATE DATABASE db_s
DEFAULT CHARACTER SET = latin
DEFAULT COLLATE = latin_swedish_ci;



DROP TABLE departments;
CREATE DATABASE test;
CREATE TABLE employees(
e_id VARCHAR(8)NOT NULL PRIMARY KEY,
e_name VARCHAR(8),
sex VARCHAR(2)DEFAULT '男',
professional VARCHAR(6),
political VARCHAR(8),
eduction VARCHAR(8),
birth DATE,
marry VARCHAR(8),
gz_time DATE,
d_id VARCHAR(5),
bz VARCHAR(1)DEFAULT '是'
);
CREATE TABLE departments(
d_id VARCHAR(5)NOT NULL PRIMARY KEY,
d_name VARCHAR(10)NOT NULL
);
CREATE TABLE salary(
e_id VARCHAR(5)NOT NULL,
`month` DATE,
jib_in FLOAT(6,2),
jix_in FLOAT(6,2),
jint_in FLOAT(6,2),
gj_out FLOAT(6,2),
tax_out FLOAT(6,2),
qt_out FLOAT(6,2)
);
ALTER TABLE salary ADD CONSTRAINT fk_employees_e_id FOREIGN KEY(e_id) 
REFERENCES employees(e_id);
DROP TABLE students;
CREATE TABLE students(
`Name` CHAR(10),
sex CHAR(2)DEFAULT'男',
xinqu CHAR(10));

INSERT INTO students VALUES('李明','男','音乐'),
			   ('张君','女','电影');
 
 SHOW DATABASES;
 CREATE TABLE students1 SELECT * FROM students;
 DELETE  FROM students;
 DROP DATABASE test;
  
 INSERT INTO departments VALUES ('A001','办公室'),
				('A002','人事处'),
				('A003','宣传部'),
				('A004','教务处'),
				('A005','科技处'),
				('A006','后勤处'),
				('B001','信息学院'),
				('B002','艺术学院'),
				('B003','外语学院'),
				('B004','金融学院'),
				('B005','建筑学院');
SELECT * FROM dapartments;
 DELETE FROM students;
 SHOW TABLES;
 
 DROP DATABASE XXFY;
CREATE DATABASE XXFY; 
USE XXFY;
CREATE TABLE students(
s_no CHAR(10) PRIMARY KEY COMMENT '学号',
s_nane CHAR(10)UNIQUE COMMENT '姓名',
sex CHAR(2)DEFAULT '男',
birthday DATE,
d_no CHAR(8) COMMENT '所在系部',
address VARCHAR(20) COMMENT '家庭地址',
phone VARCHAR(20) COMMENT '联系电话',
photo BLOB COMMENT '照片',
INDEX department(d_no),
INDEX adress_index(address)
);

CREATE TABLE course(
c_no CHAR(4) PRIMARY KEY,
c_name VARCHAR(10)COMMENT '课程名',
hours INT COMMENT '课时',
`Type` VARCHAR(10)COMMENT '课程类型'
);

CREATE TABLE credit(
s_no CHAR(10) PRIMARY KEY COMMENT '学号',
credit INT DEFAULT'0' COMMENT '学分',
CONSTRAINT fk_studnets_s_no FOREIGN KEY(s_no)REFERENCES students(s_no)
);
CREATE TABLE department(
d_no CHAR(8)PRIMARY KEY COMMENT '院系编号',
d_name CHAR(8) COMMENT '院系名称',
CONSTRAINT d_name_index UNIQUE(d_name)
);

CREATE TABLE score(
s_no CHAR(10) COMMENT '学号',
c_no CHAR(4) COMMENT '课程号',
report FLOAT(5,1)COMMENT'分数',
PRIMARY KEY (s_no,c_no),
CONSTRAINT fk_credit_s_no FOREIGN KEY(s_no) REFERENCES credit(s_no),
CONSTRAINT fk_course_c_no FOREIGN KEY(c_no) REFERENCES course(c_no)
);

CREATE TABLE teach(
teachid INT PRIMARY KEY AUTO_INCREMENT,
t_no CHAR(8)NOT NULL,
c_no CHAR(4),
CONSTRAINT fk_score_c_no FOREIGN KEY(c_no)REFERENCES score(c_no));

CREATE TABLE teacher(
t_no CHAR(8) PRIMARY KEY COMMENT '教师号',
t_name CHAR(8) NOT NULL COMMENT '教师姓名',
d_no CHAR(8),
CONSTRAINT fk_deparment_d_no FOREIGN KEY(d_no)REFERENCES department(d_no)
);
CREATE TABLE `customer` (
  `customer_id` INT(10)PRIMARY KEY,
  `name` CHAR(20),
  `address` VARCHAR(30),
  `email` VARCHAR(30),
  `sex` CHAR(2),
  `card_id` CHAR(20)
);
DROP TABLE goods;
CREATE TABLE `goods` (
  `good_id` INT(11)PRIMARY KEY,
  `good_name` VARCHAR(20),
  `unitprice` DECIMAL(10,2),
  `category` SMALLINT(6),
  `provider` VARCHAR(50)
);

DROP TABLE purchase;
CREATE TABLE purchase (
  order_id VARCHAR(20),
  `customer_id` INT(10),
  `good_id` INT(10),
  `nums` INT(11)
);

CREATE TABLE 1(a INT NOT NULL,
c INT NOT NULL);
ALTER TABLE purchase DROP FOREIGN KEY fk_customer_id;

ALTER TABLE purchase ADD PRIMARY KEY(order_id);
ALTER TABLE purchase ADD CONSTRAINT fk_customer_id FOREIGN KEY(customer_id) REFERENCES customer(customer_id);
ALTER TABLE purchase ADD CONSTRAINT fk_good_id FOREIGN KEY(good_id) REFERENCES goods(good_id);
ALTER TABLE purchase MODIFY nums INT(11) NOT NULL DEFAULT '0';
DROP DATABASE goods;
DROP TABLE studnet2;
CREATE TABLE studnet2(
s_no CHAR(10)PRIMARY KEY,
s_name CHAR(10)UNIQUE,
sex CHAR(2)DEFAULT '男',
birthday DATE NOT NULL,
d_no CHAR(6),
address VARCHAR(20),
phone BLOB,
INDEX department(d_no));
CREATE INDEX address_index ON student2(address(6)ASC);
ALTER TABLE course ADD UNIQUE INDEX c_name_index(c_name);
ALTER TABLE score ADD INDEX score_index(s_no,c_no);
ALTER TABLE teachers t_no PRIMARY KEY(t_name.d_no);
ALTER TABLE course DROP INDEX c_name_index;





USE ysgl;
-- 1.
CREATE INDEX index_birth ON employees(birth);
-- 2.
CREATE INDEX index_bir ON employees(E_name,birth)
-- 3.
ALTER TABLE employees ADD UNIQUE INDEX index_id(E_name);
-- 4.
ALTER TABLE employess DROP INDEX index_birth;





CREATE TABLE `user`(
user_id CHAR(8)NOT NULL PRIMARY KEY,
user_name CHAR(8)NOT NULL,
`password` DATE NOT NULL,
INDEX index_username(user_name),
UNIQUE INDEX index_id(user_id));

--  -----------------
-- 单表查询：
DROP TABLE IF EXISTS `emp`;

CREATE TABLE `emp` (
  `empno` INT(11) DEFAULT NULL,
  `ename` VARCHAR(20) DEFAULT NULL,
  `job` VARCHAR(40) DEFAULT NULL,
  `hiredate` DATE DEFAULT NULL,
  `salary` DECIMAL(10,2) DEFAULT NULL,
  `award` DECIMAL(10,2) DEFAULT NULL,
  `deptno` INT(11) DEFAULT NULL
) ENGINE=INNODB DEFAULT CHARSET=gb2312;

DROP TABLE IF EXISTS `bugs`;

CREATE TABLE `bugs` (
  `工号` CHAR(10) DEFAULT NULL,
  `姓名` CHAR(20) DEFAULT NULL,
  `部门` CHAR(20) DEFAULT NULL,
  `月份` INT(11) DEFAULT NULL,
  `缺陷数` INT(11) DEFAULT NULL,
  `职位` CHAR(50) DEFAULT NULL,
  UNIQUE KEY `id` (`工号`)
) ENGINE=INNODB DEFAULT CHARSET=gb2312;

INSERT  INTO `bugs`(`工号`,`姓名`,`部门`,`月份`,`缺陷数`,`职位`) 
VALUES ('D001','王博','研发一部',1,15,'Java开发工程师'),
('D002','朱璐','研发二部',1,7,'Java开发工程师'),
('D003','江珊珊','研发一部',1,0,'经理'),
('D004','李雪峰','研发二部',1,10,'Java开发工程师'),
('D005','王强','研发二部',1,9,'Java开发工程师'),
('D006','肖煜','研发二部',1,0,'经理'),
('D007','林曼曼','研发一部',2,12,'IOS开发工程师'),
('D008','熊婕','研发二部',2,15,'IOS开发工程师'),
('D009','杨子桐','研发二部',2,12,'IOS开发工程师'),
('D010','丁一宇','研发一部',2,8,'安卓开发工程师'),
('D011','王欣','研发一部',2,11,'安卓开发工程师'),
('D012','李又林','研发二部',2,13,'安卓开发工程师');

UPDATE bugs SET `缺陷数` = NULL WHERE `缺陷数` = 0;
UPDATE bugs SET `缺陷数` = 'NULL' WHERE `缺陷数` = 0;
UPDATE bugs SET `缺陷数` = NULL WHERE `缺陷数` = 0;
UPDATE Bugs SET 缺陷数 IS ‘null’ WHERE 缺陷数=0;

SELECT COUNT 姓名 FROM Bugs WHERE 部门=’研发一部’;

SELECT * FROM bugs;

SELECT * FROM bugs ORDER BY `月份`;
SELECT `部门`,COUNT(*) FROM bugs GROUP BY `部门`;

SELECT`部门`,`月份`, SUM(缺陷数)FROM bugs GROUP BY `部门` HAVING`月份` = 1 OR `月份` = 2;


-- -----------------------第九次 实训报告
DROP DATABASE testl;
CREATE DATABASE testl;
USE test1;

DROP TABLE IF EXISTS `dept`;

CREATE TABLE `dept` (
  `DEPTNO` INT(11) NOT NULL COMMENT '部门编号',
  `DNAME` VARCHAR(14) DEFAULT NULL COMMENT '部门名称',
  `LOC` VARCHAR(13) DEFAULT NULL COMMENT '部门地址',
  PRIMARY KEY (`DEPTNO`)
) ENGINE=INNODB DEFAULT CHARSET=gb2312;

INSERT  INTO `dept`(`DEPTNO`,`DNAME`,`LOC`) VALUES (10,'ACCOUNTING','NEW YORK'),(20,'RESEARCH','DALLAS'),(30,'SALES','CHICAGO'),(40,'OPERATIONS','BOSTON');


DROP TABLE IF EXISTS `emp`;

CREATE TABLE `emp` (
  `EMPNO` INT(11) NOT NULL COMMENT '员工编号',
  `ENAME` VARCHAR(10) DEFAULT NULL COMMENT '员工姓名',
  `JOB` VARCHAR(9) DEFAULT NULL COMMENT '员工职位',
  `MGR` INT(11) DEFAULT NULL COMMENT '员工直属领导编号',
  `HIREDATE` DATE DEFAULT NULL COMMENT '入职时间',
  `SAL` DOUBLE DEFAULT NULL COMMENT '工资',
  `COMM` DOUBLE DEFAULT NULL COMMENT '奖金',
  `DEPTNO` INT(11) DEFAULT NULL COMMENT '对应dept表的外键',
  PRIMARY KEY (`EMPNO`),
  KEY `EMP` (`DEPTNO`),
  CONSTRAINT `emp_ibfk_1` FOREIGN KEY (`DEPTNO`) REFERENCES `dept` (`DEPTNO`)
) ENGINE=INNODB DEFAULT CHARSET=gb2312;


INSERT  INTO `emp`(`EMPNO`,`ENAME`,`JOB`,`MGR`,`HIREDATE`,`SAL`,`COMM`,`DEPTNO`) VALUES (7369,'SMITH','CLERK',7902,'1980-12-17',800,NULL,20),(7499,'ALLEN','SALESMAN',7698,'1981-02-20',1600,300,30),(7521,'WARD','SALESMAN',7698,'1981-02-22',1250,500,30),(7566,'JONES','MANAGER',7839,'1981-04-02',2975,NULL,20),(7654,'MARTIN','SALESMAN',7698,'1981-09-28',1250,1400,30),(7698,'BLAKE','MANAGER',7839,'1981-05-01',2850,NULL,30),(7782,'CLARK','MANAGER',7839,'1981-06-09',2450,NULL,10),(7788,'SCOTT','ANALYST',7566,'1987-07-03',3000,NULL,20),(7839,'KING','PRESIDENT',NULL,'1981-11-17',5000,NULL,10),(7844,'TURNER','SALESMAN',7698,'1981-09-08',1500,0,30),(7876,'ADAMS','CLERK',7788,'1987-07-13',1100,NULL,20),(7900,'JAMES','CLERK',7698,'1981-12-03',950,NULL,30),(7902,'FORD','ANALYST',7566,'1981-12-03',3000,NULL,20),(7934,'MILLER','CLERK',7782,'1981-01-23',1300,NULL,10);


DROP TABLE IF EXISTS `salgrade`;
DROP TABLE `salgrade`;
CREATE TABLE `salgrade` (
  `GRADE` INT(11) DEFAULT NULL COMMENT'等级',
  `LOSAL` DOUBLE DEFAULT NULL COMMENT'最低工资',
  `HISAL` DOUBLE DEFAULT NULL COMMENT'最高工资'
) ENGINE=INNODB DEFAULT CHARSET=gb2312;

INSERT  INTO `salgrade`(`GRADE`,`LOSAL`,`HISAL`) VALUES (1,700,1200),(2,1201,1400),(3,1401,2000),(4,2001,3000),(5,3001,9999);




SELECT `EMPNO`员工编号,`ENAME` 员工姓名,`JOB` 员工工作, `MGR` 员工直属领导编号,`HIREDATE` 入职时间,`SAL` 工资, `COMM` 奖金,`DEPTNO` 对应dept表的外键 FROM emp;

SELECT `DEPTNO`部门编号, `DNAME`部门名称, `LOC`部门地址 FROM dept;

SELECT `GRADE`等级,`LOSAL`最低工资,`HISAL`最高工资 FROM salgrade;
-- 第一题
SELECT * FROM emp WHERE deptno = 30;
-- 第二题
SELECT `EMPNO` 编号,`ENAME` 姓名,`JOB` 部门号 FROM emp WHERE `JOB` = 'clerk';
-- 第三题
SELECT * FROM emp WHERE `SAL` 工资 <`COMM` 奖金;
-- 第四题
SELECT * FROM emp WHERE (`SAL`*0.6) < `COMM`;
-- 第五题
SELECT * FROM emp WHERE  `DEPTNO` = 10 OR deptno = 20 ORDER BY deptno ASC;
-- 第六题
SELECT * FROM emp WHERE (deptno =10 AND job = 'manager')OR(deptno =20 AND job='clerk')
-- 第七题
SELECT `JOB`员工工作 FROM emp WHERE `COMM` IS NOT NULL;
-- 第八题
SELECT * FROM emp WHERE `COMM` IS NULL ||`COMM` <100;
-- 第九题
SELECT * FROM emp WHERE `ENAME` LIKE 'A%' 
SELECT * FROM emp WHERE `ENAME` LIKE 'B%'
SELECT * FROM emp WHERE `ENAME` LIKE 'S%'
-- 第十题
SELECT * FROM emp WHERE ename LIKE '______';
-- 第十一题
SELECT * FROM emp WHERE `ENAME` NOT LIKE '%R%';
-- 第十二题
SELECT * FROM emp GROUP BY `ENAME`;
-- 第十三题
SELECT * FROM emp ORDER BY `JOB` DESC, `SAL` ASC;
-- 第十四题
SELECT ename,job,FORMAT(sal/30,2) 日薪 FROM emp;



-- 第十五题
SELECT * FROM emp WHERE`ENAME` LIKE '%A%';
-- 第十六题    
SELECT MAX(`SAL`)最高工资,MIN(`SAL`) 最低工资,FORMAT(AVG(`SAL`),2)平均工资 FROM emp;
-- 第十七题
SELECT MIN(`HIREDATE`)最早日期,MAX(`HIREDATE`)最晚日期 FROM emp;
-- 第十八题
SELECT * FROM emp ORDER BY `SAL` ASC LIMIT 0,5;

SELECT * FROM emp WHERE `SAL` > 1000 ORDER BY `SAL` DESC LIMIT 2,4;
-- 第十九题
SELECT deptno,COUNT(ename) FROM emp GROUP BY deptno;
-- 第十二题
SELECT job 职位,MIN(sal) 最低工资,MAX(sal) 最高工资 FROM emp GROUP BY job;
-- 第二十一题
SELECT `GRADE`等级,`LOSAL`最低工资,`HISAL`最高工资 FROM salgrade WHERE `GRADE` = 3;
-- 第二十二题
SELECT job 职位,AVG(sal)平均工资,COUNT(ename)雇员人数 
FROM emp GROUP BY job HAVING AVG(`SAL`) >2000
-- 第二十三题
SELECT job,SUM(sal)FROM emp WHERE job != 'salgrade' 
GROUP BY job HAVING SUM(sal)>5000 ORDER BY SUM(sal);




DROP TABLE IF EXISTS `course`;


CREATE TABLE `course` (
  `course_no` INT(11) NOT NULL,
  `course_name` CHAR(30) NOT NULL,
  `room` CHAR(20) DEFAULT NULL,
  PRIMARY KEY (`course_no`)
) ENGINE=INNODB DEFAULT CHARSET=gb2312;

INSERT  INTO `course`(`course_id`,`course_name`,`room`) VALUES (1,'计算机基础','D402'),(2,'操作系统','D305'),(3,'C语言','D303'),(4,'MySQL数据库程序设计','D503'),(5,'数据库原理','D511'),(6,'单片机原理','D213'),(7,'Java语言','D203'),(8,'数据结构','D506');

CREATE TABLE student(
stu_no INT(10)PRIMARY KEY AUTO_INCREMENT,
stu_name VARCHAR(10)UNIQUE,
sex CHAR(2)DEFAULT'男',
age INT(3) NOT NULL);

DROP TABLE IF EXISTS ordering;

CREATE TABLE ordering(
stu_no INT(10),
course_no INT(10),
score INT);
ALTER TABLE ordering ADD CONSTRAINT fk_course_no FOREIGN KEY(course_no) REFERENCES course(course_no)
ALTER TABLE ordering ADD CONSTRAINT fk_stu_no FOREIGN KEY(stu_no) REFERENCES student(stu_no);



INSERT INTO student VALUES(171232343,'范冰冰','女',32),
			  (170123245,'李连杰','男',51);
			  
ALTER TABLE course CHANGE room course_room VARCHAR(30)NOT NULL

ALTER TABLE course ADD INDEX (course_name,course_room)

SELECT COUNT(*)FROM student WHERE sex = '男' AND  25 < age >18;

UPDATE student SET age= age+5 WHERE stu_name LIKE '李%';

SELECT * FROM student;




-- 实验十  交叉查询和内连接查询

-- 第一题
DROP TABLE course;
SELECT * FROM tb_class;
SELECT * FROM tb_student;
SELECT * FROM tb_course;
SELECT * FROM tb_score;
CREATE TABLE tb_course(
courseno INT PRIMARY KEY,
coursename CHAR(20)UNIQUE NOT NULL,
credit TINYINT(2)NOT NULL,
coursehour TINYINT(3),
term TINYINT(2),
priorcourse INT
);
INSERT INTO tb_course VALUES (11003,'管理学',2,32,2,NULL),
			     (11005,'会计学',3,48,3,NULL),
			     (21001,'计算机基础',3,48,1,NULL),
			     (21002,'OFFICE高级应用',3,48,2,21001),
			     (21004,'程序设计',4,64,2,21001),
			     (21005,'数据库',4,64,4,21004),
			     (21006,'操作系统',4,64,5,21001),
			     (31001,'管理信息系统',3,48,3,21004),
			     (31002,'信息系统_分析与设计',2,32,4,31001),
			     (31005,'项目管理',3,48,5,31001);

-- 第一题
SELECT * FROM tb_student CROSS JOIN tb_score;

-- 第二题

SELECT tb_score.* FROM tb_score,tb_student WHERE
tb_score.studentno = tb_student.studentno AND
sex = '女';

-- 第三题

SELECT studentno,studentname,native,s.classno 
FROM tb_student s, tb_class c WHERE
s.`classNo` = c.`ClassNo` AND
 deparment = '会计学院';

-- 第四题

SELECT studentno,studentname,native,s.classno 
FROM tb_student s,tb_class c WHERE
s.classno = c.classno AND deparment = '计算机学院';

-- 第五题

SELECT s.studentno,s.studentname,score
FROM tb_student s,tb_score c,tb_course a
 WHERE s.studentno = c.courseno AND
a.courseno =  c.courseno AND a.coursename = '管理学';



-- 第六题

SELECT a.studentno,a.studentname,score
FROM tb_student a,tb_score b,tb_course c 
WHERE a.studentno = b.studentno AND c.courseno = b.courseno 
AND c.coursename = '会计学';

-- 第七题

SELECT a.studentno,a.studentname,
c.coursename,c.courseno,score
FROM tb_student a,tb_score b,tb_course c WHERE
a.studentno = b.`studentNo` AND c.courseno = b.`courseNo`
AND c.coursename = '计算机基础';


-- 第八题

SELECT a.`coursehour`,a.`coursename`,a.`courseno`,
a.`credit`,a.`priorcourse`,a.`term`
FROM tb_course a,tb_course b WHERE 
b.coursename = '计算机基础' AND b.`credit`= a.`credit`
AND a.`coursename` != '计算机基础';

-- 第九题


SELECT a.`coursehour`,a.`coursename`,a.`courseno`,
a.`credit`,a.`priorcourse`,a.`term`
FROM tb_course a,tb_course b WHERE 
b.coursename = '数据库' AND b.`priorcourse`= a.`priorcourse`
AND a.`coursename` != '数据库';





SELECT a.studentNo,studentName,score FROM tb_student a,tb_course b,tb_score c 
WHERE a.`studentNo`=c.`studentNo` AND b.`courseNo`=c.`courseNo` AND courseName='管理学';


SELECT a.studentNo,studentName,score FROM tb_student a,tb_course b,tb_score c 
WHERE a.`studentNo`=c.`studentNo` AND b.`courseNo`=c.`courseNo` AND courseName='会计学';



SELECT a.studentNo,studentName,courseName,b.`courseNo`,score FROM tb_student a,
tb_course b,tb_score c WHERE a.`studentNo`=c.`studentNo` 
AND b.`courseNo`=c.`courseNo` AND courseName='计算机基础';



SELECT a.courseNo,a.courseName,a.credit,a.courseHour,a.term,a.priorCourse 
FROM tb_course a,tb_course b WHERE b.`courseName`='计算机基础' 
AND b.`credit`=a.`credit` AND a.`courseName`!='计算机基础';



SELECT a.courseNo,a.courseName,a.credit,a.courseHour,a.term,a.priorCourse 
FROM tb_course a,tb_course b WHERE b.`courseName`='计算机基础' 
AND b.`credit`=a.`credit` AND a.`courseName`!='数据库';


-- 实训报告 《十一》

-- 第一题
SELECT a.`studentNo`,a.`studentName`,b.`courseno`,score
FROM tb_student a NATURAL JOIN tb_course b NATURAL JOIN tb_score;


-- 第二题
SELECT a.`studentNo` 学号,a.`studentName` 姓名,b.classno 班级编号,
b.`ClassName` 班级名称,b.`deparment` 院系名称
FROM tb_student a NATURAL JOIN tb_class b ;

-- 第三题
SELECT a.`studentNo`,a.`studentName`,sex,
a.`ClassNo`,b.`courseNo`,b.`score`
FROM tb_student a LEFT OUTER JOIN tb_score b 
ON a.`studentNo` = b.`studentNo`;

-- 第四题
SELECT a.`studentName`,a.`studentNo`,sex,a.`classNo`,
b.`studentNo`,b.`score`
FROM tb_student a RIGHT OUTER JOIN tb_score b
ON a.`studentNo` = b.`studentNo`;

-- 第五题
SELECT studentno FROM tb_score,tb_course
WHERE tb_score.`courseNo` = tb_course.`courseno` AND
coursename = '计算机基础'
UNION
SELECT studentno FROM tb_score,tb_course
WHERE tb_score.`courseNo` = tb_course.`courseno` AND
coursename = '程序设计'；

-- 第六题  
-- 6.使用union all查询选修了‘管理学’或‘计算机基础’的学生学号；
SELECT studentno FROM tb_score,tb_course
WHERE tb_score.`courseNo` = tb_course.`courseno` AND 
coursename = '管理学'
UNION ALL
SELECT studentno FROM tb_score,tb_course
WHERE tb_score.`courseNo` = tb_course.`courseno` AND
coursename = '计算机基础';

SELECT a.* FROM tb_student a,tb_class b
WHERE a.`classNo` = b.`ClassNo` AND 
grade IN (SELECT grade FROM tb_class WHERE grade = '2013')
AND studentname != '张晓勇'

SELECT *FROM tb_student WHERE classno IN 
(SELECT classno FROM tb_class WHERE grade =2013)



-- 实训报告十二

-- 第一题
SELECT studentno,studentname FROM tb_student WHERE classNo IN
(SELECT classno FROM tb_class WHERE classname = '信息系统14-1班'); 

-- 第二题
SELECT studentno,studentname FROM tb_student WHERE studentno IN
(SELECT studentno FROM tb_score a,tb_course b WHERE 
a.`courseNo`=b.`courseno`AND coursename = '计算机基础');

-- 第三题
SELECT studentno,score FROM tb_score WHERE courseno=
(SELECT courseno FROM tb_course WHERE coursename = '管理学')

-- 第四题
SELECT * FROM tb_course WHERE credit >
(SELECT credit FROM tb_course WHERE coursename = '管理学')

-- 第五题
SELECT * FROM tb_course WHERE credit <
(SELECT credit FROM tb_course WHERE coursename = '管理学')

-- 第六题
SELECT * FROM tb_course WHERE credit =
(SELECT credit FROM tb_course WHERE coursename = '管理学')

-- 第七题
SELECT * FROM tb_student WHERE YEAR(birthday) =
(SELECT  YEAR(birthday) FROM tb_student WHERE studentname = '黄菊' 
AND studentname = '黄菊')

-- 第八题
SELECT * FROM tb_student WHERE classno = 
(SELECT classno FROM tb_student WHERE studentname = '黄菊')
AND studentname!='黄菊'

