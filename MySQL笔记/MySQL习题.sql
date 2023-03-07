CREATE DATABASE ahead_tb;
USE ahead_tb;
CREATE TABLE student(
stuld INT PRIMARY KEY AUTO_INCREMENT,
stuNo VARCHAR(10)NOT NULL UNIQUE,
`name` VARCHAR(20)NOT NULL,
age INT(3)NOT NULL,
sex CHAR(2)NOT NULL
);
CREATE TABLE Course(
cld INT,
cNo VARCHAR(10)NOT NULL,
cName VARCHAR(20)NOT NULL
);
CREATE TABLE SC(
scld INT PRIMARY KEY AUTO_INCREMENT,
stuld INT,
cld INT,
score DECIMAL(4,1)DEFAULT'0',
remark TEXT,
CONSTRAINT fk_stuld_stident_stuld FOREIGN KEY(stuld) REFERENCES student(stuld)
);

ALTER TABLE student ADD INDEX index_age (age);

ALTER TABLE student MODIFY sex CHAR(3)NOT NULL;

ALTER TABLE SC DROP remark;

ALTER TABLE Course MODIFY cld INT AUTO_INCREMENT PRIMARY KEY;

ALTER TABLE SC ADD CONSTRAINT fk_cld_Course_cld FOREIGN KEY(cld) REFERENCES Course(cld);

ALTER TABLE Course ADD CONSTRAINT un_cNo UNIQUE(cNo);

ALTER TABLE student ALTER sex SET DEFAULT'男';

ALTER TABLE student ADD INDEX index_name (NAME);

INSERT INTO student(stuNo,`name`,age,sex)VALUES('201911000','武乐萍','19','男');

INSERT INTO student(stuNo,`name`,age,sex)VALUES('201965466','黄远林','19','男');

INSERT INTO Course (cNo,cName)VALUES('1','ps');

INSERT INTO Course (cNo,cName)VALUES('2','MySQL');

INSERT INTO Course (cNo,cName)VALUES('3','English;');

INSERT INTO Course (cNo,cName)VALUES('4','CLanguage');

SELECT * FROM student;

SELECT * FROM Course;

SELECT * FROM SC;

SHOW CREATE TABLE student;

SHOW CREATE TABLE Course;

SHOW CREATE TABLE SC;

SHOW INDEX FROM Course;

DROP TABLE SC;

DROP TABLE Course;

DROP TABLE student;

DROP DATABASE ahead_tb;

INSERT INTO tb_class(classNo,className,department,grade,classNum)
VALUES('AC1301','会计13-1班','会计学院','2013','35'),
('AC1302','会计13-2班','会计学院','2013','35'),
('CS1401','计算机14-1','计算机学院','2014','35'),
('IS1301,','信息系统13-1','信息学院','2013','null'),
('IS1401','信息系统14-1班','信息学院','null','30');

CREATE TABLE tb_student(
studentNO CHAR(20),
studentName VARCHAR(10),
sex CHAR(2),
birthday DATE,
native VARCHAR(10),
nation CHAR(10),
classNo CHAR(10));

INSERT INTO tb_student(studentNo,studentName,sex,birthday,native,nation,classNo)
VALUES('2013110101','张晓勇','男','1997-12-11','山西','汉','AC1301'),
('2013110103','王一敏','女','1996-03-25','河北','汉','AC1301'),
('2013110201','江山','女','1996-09-17','内蒙古','锡伯','AC1302'),
('2013110202','李明','男','1996-01-14','广西','壮','AC1302'),
('2013310101','黄菊','女','1995-09-30','北京','汉','IS1301'),
('2013310103','吴昊','男','1995-11-18','河北','汉','IS1301'),
('2014210101','刘涛','男','1997-04-03','湖南','铜','CS1401'),
('2014210102','郭志坚','男','1997-02-21','上海','汉','CS1401'),
('2014310101','王林','男','1996-10-09','河南','汉','IS1401'),
('2014310102','李怡然','女','1996-12-31','辽宁','汉','IS1401');


CREATE TABLE tb_course(
courseNo CHAR(6),
courseName VARCHAR(20),
credit CHAR(2),
courseHour CHAR(2),
term CHAR(2),
priorCourse VARCHAR(10));

INSERT INTO tb_course
VALUES ('11003','管理学','2','32','2',' '),
('11005','会计学','3','48','3',' '),
('21001','计算机基础','3','48','1',' '),
('21002','OFFICE高级应用','3','48','2','21001'),
('21004','程序设计','4','64','2','21001'),
('21005','数据库','4','64','4','21004'),
('21006','操作系统','4','64','5','21001'),
('31001','管理信息系统','3','48','3','21004'),
('31002','管理信息_分析与设计','2','32','4','31001'),
('31005','项目管理','3','48','5','31001');


CREATE TABLE tb_score(
studentNo CHAR(20),
course VARCHAR(20),
score CHAR(2));

INSERT INTO tb_score VALUES ('2013110101','11003','90'),
('2013110101','21001','86'),
 ('2013110103','11003','89'),
 ('2013110103','21001','88'),
 ('2013110201','11003','78'),
 ('2013110201','21001','92'),
 ('2013110202','11003','82'),
 ('2013110202','21001','85'),
 ('2013310101','21004','83'),
 ('2013310101','31002','68'),
 ('2013310103','21004','80'),
 ('2013310103','31002','76'),
 ('2014210101','21002','93'),
 ('2014210101','21004','89'),
 ('2014210102','21002','95'),
 ('2014201102','21004','88'),
 ('2014310101','21001','79'),
 ('2014310101','21004','80'),
 ('2014310102','21001','91'),
 ('2014310102','21004','87');

UPDATE tb_class SET className=88,grade='2019',department='信息分院';
UPDATE tb_class SET department='咸丰大学' WHERE classNo='AC1302';

SELECT * FROM tb_class;

SHOW CREATE TABLE tb_class;

-- 条件是用来过滤行的

CREATE TABLE tb_sp(
sno CHAR(10),
pno VARCHAR(20)UNIQUE,
`status` INT DEFAULT '1',
qty INT NOT NULL,
CONSTRAINT PRIMARY KEY(sno));

ALTER TABLE tb_sp DROP PRIMARY KEY;

ALTER TABLE tb_sp ADD CONSTRAINT pk_sno PRIMARY KEY;-- alter语句添加主键

ALTER TABLE tb_sp DROP INDEX pno;

ALTER TABLE tb_sp ADD CONSTRAINT uq_pno UNIQUE(pno);

ALTER TABLE 