# mysql 触发器

## 0、触发器的使用

>   案例：当向学⽣信息表添加、删除、修改学⽣信息时使⽤触发器⾃定进⾏⽇志记录

```sql
-- 学⽣信息表
create table students(
  stu_num char(4) primary key,
  stu_name varchar(20) not null,
  stu_gender char(2) not null,
  stu_age int not null
);
-- 学⽣信息操作⽇志表
create table stulogs(
  id int primary key auto_increment,
  time TIMESTAMP,
  log_text varchar(200)
);

-- 当向students表中添加学⽣信息时，同时要在 stulogs表中添加⼀条操作⽇志
insert into students(stu_num,stu_name,stu_gender,stu_age)
values('1004','夏利','⼥',20);
-- ⼿动进⾏记录⽇志
insert into stulogs(time,logtext) values(now(),'添加1004学⽣信息');
```

## 1、语法

### 1、创建触发器

```sql
create trigger tri_name
<before|after> -- 定义触发时机
<insert|delete|update> -- 定义DML类型
ON <table_name>
for each row -- 声明为⾏级触发器（只要操作⼀条记录就触发触发器执⾏⼀
次）
sql_statement -- 触发器操作

-- 创建触发器：当学⽣信息表发⽣添加操作时，则向⽇志信息表中记录⼀条⽇志
create trigger tri_test1
after insert on students
for each row
insert into stulogs(time,lo_text) values(now(), concat('添
加',NEW.stu_num,'学⽣信息'));
```

### 2、查看触发器

```sql
show triggers;
```

### 3、测试触发器

>   我们创建的触发器是在students表发⽣insert操作时触发，我们只需执⾏学⽣信息的添加
>   操作

```sql
-- 测试1：添加⼀个学⽣信息，触发器执⾏了⼀次
insert into students(stu_num,stu_name,stu_gender,stu_age)
values('1005','⼩明','男',20);

-- 测试2：⼀条SQL指令添加了2条学⽣信息，触发器就执⾏了2次
insert into students(stu_num,stu_name,stu_gender,stu_age)
values('1006','⼩刚','男',20),('1007','李磊','男',20);
```

### 4、删除触发器

```sql
drop trigger tri_test1;
```

### 5、NEW与OLD

>   触发器⽤于监听对数据表中数据的insert、delete、update操作，
>
>   在触发器中通常处理⼀些DML的关联操作；
>
>   我们可以使⽤ NEW 和 OLD 关键字在触发器中获取触发这个触发器的DML操作的数据

-   **NEW** : 在触发器中⽤于获取insert操作添加的数据、update操作修改后的记录
-   **OLD**：在触发器中⽤于获取delete操作删除前的数据、update操作修改前的数据

#### 1、NEW

>   insert操作中：NEW表示添加的新记录

```sql
create trigger tri_test1
after insert on students
for each row
insert into stulogs(time,lo_text) values(now(), concat('添加',NEW.stu_num,'学⽣信息'));
```

>   update操作中：NEW 表示修改后的数据

```sql
-- 创建触发器 : 在监听update操作的触发器中，可以使⽤NEW获取修改后的数据
create trigger tri_test2
after update on students for each row
insert into stulogs(time,lo_text) values(now(), concat('修改学⽣信息为：',NEW.stunum,NEW.stuname));
```

#### 2、OLD

>   delete操作中：OLD表示删除的记录

```sql
create trigger tri_test3
after delete on students for each row
insert into stulogs(time,lo_text) values(now(), concat('删除',OLD.stu_num,'学⽣信息'));
```

>    update操作中：OLD表示修改前的记录

```sql
create trigger tri_test2
after update on students for each row
insert into stulogs(time,lo_text) values(now(), concat('将学⽣姓名从【',OLD.stu_name,'】修改为【',NEW.stu_name,'】'));
```

## 3、总结

### 1、优点

-   触发器是⾃动执⾏的，当对触发器相关的表执⾏响应的DML操作时⽴即执⾏；
-   触发器可以实现表中的数据的级联操作（关联操作），有利于保证数据的完整性；
-   触发器可以对DML操作的数据进⾏更为复杂的合法性校验

### 2、缺点

-   使⽤触发器实现的业务逻辑如果出现问题将难以定位，后期维护困难；
-   ⼤量使⽤触发器容易导致代码结构杂乱，增加了程序的复杂性；
-   当触发器操作的数据量⽐较⼤时，执⾏效率会⼤⼤降低。

### 3、使用建议

-   **在互联网项目中，应避免适应触发器**；
-   对于并发量不⼤的项⽬可以选择使⽤存储过程，
-   **但是在互联网引用中不提倡使用存储过程**
    -   原因：
        -   存储过程将实现业务的逻辑交给数据库处理，
        -   ⼀则增减了数据库的负载，
        -   ⼆则不利于数据库的迁移