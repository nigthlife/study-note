
-- 1：按以上要求创建表结构
-- 学生信息表
create table Student( 
stuId number primary key,  -- 学生id
stuNo varchar(10) unique not null,  -- 学号
"name" varchar2(20) not null,       -- 姓名
age number(2)  check(age >1 and age <100)not null,-- 年龄
sex char(2)  check(sex in('男','女'))not null  -- 性别
);

-- 课程表
create table Course(
cId number primary key,   -- 课程id
cNo varchar2(10) unique not null,  -- 课程编号
cName varchar2(20) not null -- 课程名称
);

-- 学生选课表
create table Sc(
scId number primary key,    -- 选课id
stuId number,       -- 学生id
cId number,         -- 课程id
score number(4,1) default 0 check(score > 0 and score < 100),-- 成绩
constraints FK_Sc_Student_stuId foreign key(stuId) 
references Student(stuId),
constraints FK_Sc_Coutse_cId foreign key(cId)
references Course(cId)
);

-- 2：分别写30条insert语句，分别向学生表，课程表，各插入10条，
create Sequence s_SC;

 
  -- 向学生信息表

create Sequence S_Student;

insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'000','神仙',99,'男');
insert into Student(stuId,stuno,"name",age,sex)
       values(S_Student.nextval,'001','艾路迪',20,'男');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'002','温蒂',21,'男');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'003','海明威',65,'男');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'004','红太狼',25,'女');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'005','徐圆梦',22,'男');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'006','宋孟君',20,'男');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'007','王麦兜',22,'男');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'008','唐小林',19,'女');              
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'009','白沐',20,'女');      




-- 课程表
create Sequence s_Course;
-- drop Sequence s_Course;

insert into Course(cId,Cno,Cname) values(s_Course.nextval,000,'java进阶深入');              
insert into Course(cId,Cno,Cname) values(s_Course.nextval,001,'python简单玩耍');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,002,'三年精通语文');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,003,'三年高考');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,004,'五年自卑');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,005,'c++');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,006,'css');              
insert into Course(cId,Cno,Cname) values(s_Course.nextval,007,'我的mysql');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,008,'编程数学');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,009,'旅游英语');              


-- 学生选课表
delete from Sc;
drop Sequence s_Sc;
create Sequence s_SC;
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,001,006,78.5);    
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,001,005,60);            
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,003,008,45.5); 
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,003,007,85.5);      
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,003,009,87.5);                
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,004,007,83.0);   
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,004,001,87.0);                           
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,008,003,70.5);
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,008,009,71.5);     
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,009,004,66);
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,009,008,64);                   
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,006,001,97);                           
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,006,009,90);                           
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,002,001,89);                  
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,002,002,79);                               
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,007,005,55.5);               
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,007,002,59.2);
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,006,007,78);
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,007,006,99);
insert into SC(SCID,STUID,CID,SCORE)values(s_SC.nextval,007,004,58);
  
-- 选课表插入20条“非常逼真的数据”，不允许随便给一些垃圾数据
-- （要求：学生的学号固定为：S000~S009，课程号固定为:C000~C009）。
-- 3：查询所有学生的姓名、性别、年龄（使用别名：姓名、性别、年龄）
select "name" 姓名,sex 性别,age 年龄 from Student;

-- 4：查询性别为'男'的学生的“学号、姓名，年龄”
select stuNo 学号,"name" 姓名,age 年龄 from Student where sex = '男';

-- 5：查询学号为S005的同学所选的课程信息---“学号，课程名称，成绩”3.
 select * from Student  left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid where stuNo = 005;

-- 6：修改课程名称类型为nvarchar2(100)
alter table Course modify cName varchar2(100) not null;

-- 7：向课程表中添加一列 描述(remark)
alter table Course add remark varchar2(100) default null;

-- 8: 给课程名称列添加唯一索引
alter table Course add unique (cName);

-- 9：统计学号为“S005”学生选课数量
 select count(1) from Student  left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid
 where stuNo = 005 group by stuNo;

-- 10：查询课程表中课程名称包含“言”字的所有课程信息
select * from Course where cName like '%言%';

-- 11：统计年龄在18-20岁之间的学生总数
select count(1) from Student where age between 18 and 20;
 
-- 12：查询学号为“S006”所选课程的总成绩，平均成绩
select sum(score),avg(score) from Student left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid
 where stuNo = 006;

-- 13：查询课程号为"C003"的最高成绩，最低成绩，平均成绩
select max(score),min(score),avg(score) from Course c left join Sc
on c.cid = Sc.Cid where c.cid = 003;

-- 14：查询至少选修两门课程的学生学号，姓名
select stuNo, "name" from  Student left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid
 group by  Sc.stuid,stuNo, "name" having count(Sc.stuid) > 1; 

-- 15：删除“s002”同学的“c001”课程的成绩
update  Sc set score = 0 where stuid in (select Sc.stuid from Student left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid where Sc.cid = 001 and Sc.stuid = 002); 

-- 16：更新选修课程为'C008'的成绩<60分的成绩为59分。
update  Sc set score = 59 where cid = 008 and score < 60;

-- 17：查询平均成绩在80分以上的课程编号和课程名称, 并按课程编号升序排序
select c.cid,c.cName from Course c left join Sc on c.cid = Sc.Cid 
group by c.cid,c.cName ,c.cno having avg(Sc.score) > 80 order by c.cno desc;

-- 18：查询全部学生都选修的课程的课程号和课程名
select cno 课程号,cname 课程名 from course c
where c.cid=(select sc.cid from sc group by sc.cid
having count(stuid)>(select count(s.stuid) from student s));
