-- DDL 数据定义语言  create  alter  drop
-- alter: 添加列
alter table emp
add sex char(1) default('0') not null ;

-- address nvarchar(30)
alter table emp
modify sex char(2);

-- 删除表drop
select * from tab;

create table emp88 as select * from emp where 1=2;
select * from emp88;
create table emp99 as select * from emp where sal > 1500;
select * from emp99;
drop table emp99;

-- 查询回收站中的内容
select * from recyclebin;

-- 闪回(还原)
flashback table EMP99 to before drop;

-- drop table 表名 purge; -- 不经过回收站
drop table emp99 purge;

-- 清空回收站
purge recyclebin;

-- DML 数据操纵语言  update insert delete select
-- select
-- insert 
-- insert into 表名 (列名...) values (值...);
-- insert into 表名 values (该表所有列的值,位置一一对应);
-- insert into 表名 (列名...) select (列名...) from 数据源;
create table emppp as select ename, sal from emp where 1=2;

select * from emppp;

insert into emppp (ename,sal) select ename,sal from emp;

-- update 
-- update 表名 set 列名=值,... where 条件;

-- delete 
-- delete from 表名 [where 条件];
delete from emppp;
commit; --TCL 事务控制语言 commit, rollback.

-- truncate 
-- truncate table 表名;
truncate table emppp;

select * from emppp;

-- delete   <=>   truncate
-- DML              DDL
--逐行删除       先摧毁表，再创建表
--可以恢复        不能恢复
-- 比较快          慢
-- 删除会产生碎片  不会产生碎片

-- 约束
-- primary key
create table students
(
   stuid number primary key,
   stuName nvarchar2(100)
)
drop table students purge;
create table students
(
   stuid number,
   stuName nvarchar2(100),
   constraints PK_STUDNETS_STUID primary key (stuid)
)
insert into students values (1,'zs');
insert into students values (1,'ls');

create table students
(
   stuid number,
   stuName nvarchar2(100)
   );
   
alter table students
add constraints PK_STUDNETS_STUID primary key (stuid);

-- 唯一约束 unique
create table students
(
   stuid number,
   stuName nvarchar2(100),
   idcard char(18) unique
);
create table students
(
   stuid number,
   stuName nvarchar2(100),
   idcard char(18),
   constraints U_STUDENTS_IDCARD unique(idCard)
);

-- 检查check
drop table students purge;
create table students
(
   stuId number,
   stuName nvarchar2(100),
   stuSex nchar(1) check(stuSex in ('男','女')),
   stuAge number(3) check(stuAge >= 1 and stuAge < 150)
);
insert into students
  (stuid, stuname, stusex, stuage)
values
  (1, 'xa', '男', 19);

select * from students;

create table students
(
   stuId number,
   stuName nvarchar2(100),
   stuSex nchar(1),
   constraints CK_STUDENTS_STUSEX check(stuSex in ('男','女'))
);

-- not null
alter table students
modify stuName nvarchar2(100) not null;

-- default 
create table students
(
   stuId number,
   stuName nvarchar2(100),
   stuSex nchar(1) default('男'),
   constraints CK_STUDENTS_STUSEX check(stuSex in ('男','女'))
);
insert into students
  (stuid, stuname)
values
  (1, 'xa');
select * from students;

-- foreign key
create table classs
(
    clsId number primary key,
    clsName nvarchar2(20)
);
insert into classs values(2,'19Test'); 
--insert into classs values(3,'19Test2'); 


create table students
(
   stuId number,
   stuName nvarchar2(100),
   stuSex nchar(1) default('男'),
   clsId number,
   constraints FK_STUDENTS_CLASSS_CLSID foreign key(clsId) references Classs(clsId)
);


insert into students
  (stuid, stuname,clsId)
values
  (1, 'xa', 1);














