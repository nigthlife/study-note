
-- 1��������Ҫ�󴴽���ṹ
-- ѧ����Ϣ��
create table Student( 
stuId number primary key,  -- ѧ��id
stuNo varchar(10) unique not null,  -- ѧ��
"name" varchar2(20) not null,       -- ����
age number(2)  check(age >1 and age <100)not null,-- ����
sex char(2)  check(sex in('��','Ů'))not null  -- �Ա�
);

-- �γ̱�
create table Course(
cId number primary key,   -- �γ�id
cNo varchar2(10) unique not null,  -- �γ̱��
cName varchar2(20) not null -- �γ�����
);

-- ѧ��ѡ�α�
create table Sc(
scId number primary key,    -- ѡ��id
stuId number,       -- ѧ��id
cId number,         -- �γ�id
score number(4,1) default 0 check(score > 0 and score < 100),-- �ɼ�
constraints FK_Sc_Student_stuId foreign key(stuId) 
references Student(stuId),
constraints FK_Sc_Coutse_cId foreign key(cId)
references Course(cId)
);

-- 2���ֱ�д30��insert��䣬�ֱ���ѧ�����γ̱�������10����
create Sequence s_SC;

 
  -- ��ѧ����Ϣ��

create Sequence S_Student;

insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'000','����',99,'��');
insert into Student(stuId,stuno,"name",age,sex)
       values(S_Student.nextval,'001','��·��',20,'��');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'002','�µ�',21,'��');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'003','������',65,'��');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'004','��̫��',25,'Ů');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'005','��Բ��',22,'��');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'006','���Ͼ�',20,'��');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'007','����',22,'��');
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'008','��С��',19,'Ů');              
insert into Student(stuId,Stuno,"name",age,sex)
       values(S_Student.nextval,'009','����',20,'Ů');      




-- �γ̱�
create Sequence s_Course;
-- drop Sequence s_Course;

insert into Course(cId,Cno,Cname) values(s_Course.nextval,000,'java��������');              
insert into Course(cId,Cno,Cname) values(s_Course.nextval,001,'python����ˣ');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,002,'���꾫ͨ����');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,003,'����߿�');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,004,'�����Ա�');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,005,'c++');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,006,'css');              
insert into Course(cId,Cno,Cname) values(s_Course.nextval,007,'�ҵ�mysql');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,008,'�����ѧ');               
insert into Course(cId,Cno,Cname) values(s_Course.nextval,009,'����Ӣ��');              


-- ѧ��ѡ�α�
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
  
-- ѡ�α����20�����ǳ���������ݡ�������������һЩ��������
-- ��Ҫ��ѧ����ѧ�Ź̶�Ϊ��S000~S009���γ̺Ź̶�Ϊ:C000~C009����
-- 3����ѯ����ѧ�����������Ա����䣨ʹ�ñ������������Ա����䣩
select "name" ����,sex �Ա�,age ���� from Student;

-- 4����ѯ�Ա�Ϊ'��'��ѧ���ġ�ѧ�š����������䡱
select stuNo ѧ��,"name" ����,age ���� from Student where sex = '��';

-- 5����ѯѧ��ΪS005��ͬѧ��ѡ�Ŀγ���Ϣ---��ѧ�ţ��γ����ƣ��ɼ���3.
 select * from Student  left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid where stuNo = 005;

-- 6���޸Ŀγ���������Ϊnvarchar2(100)
alter table Course modify cName varchar2(100) not null;

-- 7����γ̱������һ�� ����(remark)
alter table Course add remark varchar2(100) default null;

-- 8: ���γ����������Ψһ����
alter table Course add unique (cName);

-- 9��ͳ��ѧ��Ϊ��S005��ѧ��ѡ������
 select count(1) from Student  left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid
 where stuNo = 005 group by stuNo;

-- 10����ѯ�γ̱��пγ����ư������ԡ��ֵ����пγ���Ϣ
select * from Course where cName like '%��%';

-- 11��ͳ��������18-20��֮���ѧ������
select count(1) from Student where age between 18 and 20;
 
-- 12����ѯѧ��Ϊ��S006����ѡ�γ̵��ܳɼ���ƽ���ɼ�
select sum(score),avg(score) from Student left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid
 where stuNo = 006;

-- 13����ѯ�γ̺�Ϊ"C003"����߳ɼ�����ͳɼ���ƽ���ɼ�
select max(score),min(score),avg(score) from Course c left join Sc
on c.cid = Sc.Cid where c.cid = 003;

-- 14����ѯ����ѡ�����ſγ̵�ѧ��ѧ�ţ�����
select stuNo, "name" from  Student left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid
 group by  Sc.stuid,stuNo, "name" having count(Sc.stuid) > 1; 

-- 15��ɾ����s002��ͬѧ�ġ�c001���γ̵ĳɼ�
update  Sc set score = 0 where stuid in (select Sc.stuid from Student left join Sc on Student.Stuid = Sc.Stuid
 left join Course on Sc.Cid = Course.Cid where Sc.cid = 001 and Sc.stuid = 002); 

-- 16������ѡ�޿γ�Ϊ'C008'�ĳɼ�<60�ֵĳɼ�Ϊ59�֡�
update  Sc set score = 59 where cid = 008 and score < 60;

-- 17����ѯƽ���ɼ���80�����ϵĿγ̱�źͿγ�����, �����γ̱����������
select c.cid,c.cName from Course c left join Sc on c.cid = Sc.Cid 
group by c.cid,c.cName ,c.cno having avg(Sc.score) > 80 order by c.cno desc;

-- 18����ѯȫ��ѧ����ѡ�޵Ŀγ̵Ŀγ̺źͿγ���
select cno �γ̺�,cname �γ��� from course c
where c.cid=(select sc.cid from sc group by sc.cid
having count(stuid)>(select count(s.stuid) from student s));
