-- DDL ���ݶ�������  create  alter  drop
-- alter: �����
alter table emp
add sex char(1) default('0') not null ;

-- address nvarchar(30)
alter table emp
modify sex char(2);

-- ɾ����drop
select * from tab;

create table emp88 as select * from emp where 1=2;
select * from emp88;
create table emp99 as select * from emp where sal > 1500;
select * from emp99;
drop table emp99;

-- ��ѯ����վ�е�����
select * from recyclebin;

-- ����(��ԭ)
flashback table EMP99 to before drop;

-- drop table ���� purge; -- ����������վ
drop table emp99 purge;

-- ��ջ���վ
purge recyclebin;

-- DML ���ݲ�������  update insert delete select
-- select
-- insert 
-- insert into ���� (����...) values (ֵ...);
-- insert into ���� values (�ñ������е�ֵ,λ��һһ��Ӧ);
-- insert into ���� (����...) select (����...) from ����Դ;
create table emppp as select ename, sal from emp where 1=2;

select * from emppp;

insert into emppp (ename,sal) select ename,sal from emp;

-- update 
-- update ���� set ����=ֵ,... where ����;

-- delete 
-- delete from ���� [where ����];
delete from emppp;
commit; --TCL ����������� commit, rollback.

-- truncate 
-- truncate table ����;
truncate table emppp;

select * from emppp;

-- delete   <=>   truncate
-- DML              DDL
--����ɾ��       �ȴݻٱ��ٴ�����
--���Իָ�        ���ָܻ�
-- �ȽϿ�          ��
-- ɾ���������Ƭ  ���������Ƭ

-- Լ��
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

-- ΨһԼ�� unique
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

-- ���check
drop table students purge;
create table students
(
   stuId number,
   stuName nvarchar2(100),
   stuSex nchar(1) check(stuSex in ('��','Ů')),
   stuAge number(3) check(stuAge >= 1 and stuAge < 150)
);
insert into students
  (stuid, stuname, stusex, stuage)
values
  (1, 'xa', '��', 19);

select * from students;

create table students
(
   stuId number,
   stuName nvarchar2(100),
   stuSex nchar(1),
   constraints CK_STUDENTS_STUSEX check(stuSex in ('��','Ů'))
);

-- not null
alter table students
modify stuName nvarchar2(100) not null;

-- default 
create table students
(
   stuId number,
   stuName nvarchar2(100),
   stuSex nchar(1) default('��'),
   constraints CK_STUDENTS_STUSEX check(stuSex in ('��','Ů'))
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
   stuSex nchar(1) default('��'),
   clsId number,
   constraints FK_STUDENTS_CLASSS_CLSID foreign key(clsId) references Classs(clsId)
);


insert into students
  (stuid, stuname,clsId)
values
  (1, 'xa', 1);














