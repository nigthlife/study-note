# 存储过程

## 0、介绍

-   存储过程是事先经过编译并存储在数据库中的一段 SQL 语句的集合，
-   调用存储过程可以简化应用开发人员的很多工作，
-   减少数据在数据库和应用服务器之间的传输，对于提高数据处理的效率是有好处的。
-   存储过程思想上很简单，就是数据库 SQL 语言层面的代码封装与重用

>   ==特点==
>
>   -   封装，复用 
>       -   可以把某一业务SQL封装在存储过程中，需要用到的时候直接调用
>   -   可以接收参数，也可以返回数据
>       -    再存储过程中，可以传递参数，也可以接收返回
>   -   减少网络交互，效率提升 
>       -    如果涉及到多条SQL，每执行一次都是一次网络传输。 
>       -   而如果封装在存储过程中，我们只需要网络交互一次可能就可以

## 1、语法

>   ==关键字 `delimiter`用于指定sql的语句的结束符==

>   **1、创建存储过程**
>
>   ```sql
>   create procedure 存储过程名称 ([ 参数列表 ])
>   begin
>   	-- SQL语句
>   end
>   ```

>   **2、调用存储过程**
>
>   ```sql
>   call 名称 ([ 参数 ]
>   ```

>   **3、查看存储过程**
>
>   ```sql
>   -- 查询指定数据库的存储过程及状态信息
>   select * from information_schema.routines where routine_schema = 'xxx'; 
>   
>   -- 查询某个存储过程的
>   show create procedure 存储过程名称 ; 
>   ```

>   **4、删除**
>
>   ```sql
>   drop procedure [ if exusts ] 存储过程名称;
>   ```

>   **5、案例**
>
>   ```sql
>   -- 存储过程基本语法
>   -- 创建
>   create procedure p1()
>   begin
>   	select count(*) from student;
>   end;
>   
>   -- 调用
>   call p1();
>   
>   -- 查看
>   select * from information_schema.routines where routines_schema = 'itcast';
>   show create procedure p1;
>   
>   -- 删除
>   drop procedure if exists p1;   -- 如果p1存储过程存在就删除它，否则跳过
>   ```



## 2、变量

>   ==MySQL中变量分为：系统变量、用户自定义变量、局部变量==

>   -   ==以下如果没有指定`session、global`默认是`session`会话变量==
>   -   ==mysql服务重新启动后，所设置的全局参数会失效，想要不失效，需要配置在mysql的配置文件中配置==
>       -   关于配置文件：==linux是my.cnf，Windows是my.ini中配置==
>
>   -   ==global：全局变量针对所有的会话==
>   -   ==session：会话变量针对单个会话，在另一个会话窗口不生效==
>
>   ### **1、查看系统变量**
>
>   ```sql
>   -- 查看所有系统变量
>   show [ session | global ] variables;
>   
>   -- 使用like模糊匹配查找变量
>   show [ session | global ] variables like '变量名称的一部分';
>   
>   -- 查看指定变量的值
>   select @@[ session | global ] 系统变量名;
>   ```

>   #### **设置系统变量**
>
>   ```sql
>   set [ session | global ] 系统变量名 = 值;
>   
>   set @@[ session | global ] 系统变量名 = 值;
>   ```

>   ##### **案例**
>
>   ```sql
>   -- 查看系统变量
>   show session variables;
>   
>   -- 记得变量一部分的查询方式
>   show session variables like 'auto%';
>   show global variables like 'auto%';
>   
>   -- 记得变量名称直接使用select查询，@@符号为系统变量标识符
>   select @@global.autocommit;
>   select @@session.autocommit;
>   
>   
>   -- 设置系统变量
>   -- 开启事务自动提交
>   set session autocommit = 1;
>   
>   insert into course(id, name) value(6, 'es');
>   
>   -- 关闭事务自动提交
>   set global autocommit = 0;
>   
>   -- 查看自动提交事务变量的值
>   select @@global.autocommit;
>   ```

>   ### **2、用户自定义变量**
>
>   -   ==用户变量不用提前声明，在用的时候直接定义==
>
>   -   ==使用【`@`】符号标记为用户自定义变量==
>
>   -   ==标记的变量作用域为当前连接==
>
>   -   ==用户自定义变量初始值为null== 

>   #### **赋值**
>
>   ```sql
>   -- 支持的几种赋值方式
>   set @var_name = 值或表达式;
>   set @var_name := 值或表达式;
>   
>   -- 使用查询赋值
>   select @var_name := 值或表达式;
>   select 字段名 into @var_name from 表名;
>   ```

>   #### **案例**
>
>   ```sql
>   -- 赋值
>   set @myname = 'itcast';
>   set @myage := 10;
>   
>   -- 多个变量赋值
>   set @mygender := '男',@myhobby := 'java';
>   
>   select @mycolor := 'red';
>   
>   -- 将查询结果赋值到@mycount
>   select count(*) into @mycount from tb_user;
>   
>   -- 使用定义的变量
>   -- 查询变量的值
>   select @myname,@myage,@mygender,@myhobby;
>   
>   select @mycolor , @mycoun;
>   
>   -- 初始为null
>   select @abc;
>   ```



>   ### **3、局部变量**
>
>   -   ==访问之前，需要`declare`声明，可以用作存储过程内的局部变量和输入参数，作用域在其声明的begin....end块==

>   #### **声明**
>
>   ```sql
>   declare 变量名 变量类型 [ default 值];
>   ```

>   #### **赋值**
>
>   ```sql
>   set 变量名 = 值;
>   
>   set 变量名 := 值；
>   
>   select 字段名 into 变量名 from 表名;
>   ```

>   #### **案例**
>
>   ```sql
>   -- 声明局部变量 - declare
>   -- 赋值
>   create procedure p2()
>   begin
>   	declare stu_count int default 0;
>   	select count(*) into stu_count from student;
>   	select stu_count;
>   end;
>   
>   call p2();
>   ```

## 3、条件语句与参数

>   ### **1、if**
>
>   #### **案例**
>
>   ```sql
>   -- 根据定义的分数score变量，判定当前分数对应的分数等级。
>   -- score >= 85分，等级为优秀。
>   -- score >= 60分 且 score < 85分，等级为及格。
>   -- score < 60分，等级为不及格。
>   
>   create procedure p3()
>   begin
>   	-- 初始化score的默认值为58
>       declare score int default 58;
>       -- 这里初始result的值为null
>       declare result varchar(10);
>   
>       if score >= 85 then
>           set result := '优秀';
>       elseif score >= 60 then
>           set result := '及格';
>       else
>           set result := '不及格';
>       end if;
>       select result;
>   end;
>   
>   call p3();
>   ```

>   ### **2、参数**
>
>   -   参数的类型分三种
>       -   ==in：声明参数需要调用时传入值==
>       -   ==out：声明参数为返回值==
>       -   ==inout：声明参数既可以传入值也可以返回值==

>   #### 案例
>
>   ```sql
>   -- 根据传入(in)参数score，判定当前分数对应的分数等级，并返回(out)。
>   -- score >= 85分，等级为优秀。
>   -- score >= 60分 且 score < 85分，等级为及格。
>   -- score < 60分，等级为不及格。
>   
>   create procedure p4(in score int, out result varchar(10))
>   begin
>       if score >= 85 then
>           set result := '优秀';
>       elseif score >= 60 then
>           set result := '及格';
>       else
>           set result := '不及格';
>       end if;
>   end;
>   
>   -- 定义用户变量 @result来接收返回的数据, 用户变量可以不用
>   call p4(18, @result);
>   select @result;
>   
>   
>   -- 将传入的 200分制的分数,进行换算,换算成百分制 , 然后返回分数 ---> inout
>   create procedure p5(inout score double)
>   begin
>       set score := score * 0.5;
>   end;
>   
>   set @score = 198;
>   call p5(@score);
>   select @score;
>   ```
>
>   

>   ### **3、case**
>
>   #### 语法
>
>   ```sql
>   -- 当value的值等于值1，那么就执行语句块1中的代码，其他语句块中的代码都不执行，如果值1和值2都不等于，那么就默认执行语句3
>   case value
>   	when 值1 then 
>   		语句块1
>   	when 值2 then
>   		语句块2
>   	else
>   		语句块3
>   end case;
>   
>   -- 含义： 当条件search_condition1成立时，执行代码块1，
>   -- 当条件search_condition2成立时，执行代码块2， 否则就执行 默认代码块
>   case
>   	when search_condition1 then 
>   		代码块1
>   	when search_condition2 then 
>   		代码块2
>   	else 
>   		默认代码块
>   end CAS
>   ```
>
>   #### **案例**
>
>   ==如果判定条件有多个，多个条件之间，可以使用 and 或 or 进行连==
>
>   ```sql
>   -- 根据传入的月份，判定月份所属的季节（要求采用case结构）
>   -- 1-3月份，为第一季度
>   -- 4-6月份，为第二季度
>   -- 7-9月份，为第三季度
>   -- 10-12月份，为第四季度
>   
>   create procedure p6(in month int)
>   begin
>   	declare result varchar(10);
>   	case
>   		when month >= 1 and month <= 3 then
>   			set result := '第一季度';
>   		when month >= 4 and month <= 6 then
>   			set result := '第二季度';
>   		when month >= 7 and month <= 9 then
>   			set result := '第三季度';
>   		when month >= 10 and month <= 12 then
>   			set result := '第四季度';
>   		else
>   			set result := '非法参数';
>   	end case ;
>   	select concat('您输入的月份为: ',month, ', 所属的季度为: ',result);
>   end;
>   
>   -- 调用
>   call p6(16);
>   ```

>   ### 4、while
>
>   #### 语法
>
>   ```sql
>   -- 先判定条件，如果条件为true，则执行逻辑，否则，不执行逻辑
>   while 条件 do
>   	SQL逻辑...
>   end while;
>   ```
>
>   **案例**
>
>   ```sql
>   create procedure p7(in n int)
>   begin
>   	declare i int default 1;
>   	declare sum int default 0;
>   	while i<=n do
>   		set sum := sum+i;
>   		set i := i+1;
>   	end while;
>   	select sum;
>   end;
>   
>   call p7(100);
>   ```
>
>   

>   ### 5、repeat
>
>   ==repeat是有条件的循环控制语句, 当满足until声明的条件的时候，则退出循环==
>
>   #### 语法
>
>   ```sql
>   -- 先执行一次逻辑，然后判定until条件是否满足，如果满足，则退出。如果不满足，则继续下一次循
>   repeat
>   	SQL逻辑...
>   	until 条件
>   end repeat;
>   ```
>
>   #### 案例
>
>   ```sql
>   -- 计算从1累加到n的值，n为传入的参数值。(使用repeat实现)
>   -- 定义局部变量i作为计数器，定义局部变量sum作为和-- 每循环一次对i进行+1，当i>n时退出循环
>   create procedure p8(in n int)
>   begin
>   	declare i int default 1;
>   	declare sum int default 0;
>   	repeat
>   		set sum := sum+i;
>   		set i := i+1;
>   	until i > n
>   	end repeat;
>   	select sum;
>   	
>   end;
>   call p8(10);
>   call p8(100);
>   ```
>
>   

>   ### 6、loop
>
>   **LOOP 实现简单的循环，如果不在SQL逻辑中增加退出循环的条件，可以用其来实现简单的死循环**
>
>   -   LOOP可以配合一下两个语句使用：
>       -   leave：配合循环使用，退出循环。
>       -   iterate ：必须用在循环中，作用是跳过当前循环剩下的语句，直接进入下一次循环。
>
>   #### 案例
>
>   ```sql
>   -- 计算从1累加到n的值，n为传入的参数
>   
>   -- 定义局部变量i作为计数器，定义局部变量sum作为和
>   -- 每循环一次对i进行+1，当i>n时跳出循环---leave xx
>   create procedure p9(in n int)
>   begin
>   	declare i int default 1;
>   	declare sum int default 0;
>   	
>   	sum_loop:loop
>   		set sum := sum+i;
>   		set i := i+1;
>   		if i>n then 
>   			leave sum_loop;
>   		end if;
>       end loop sum_loop; 
>   select sum;
>   end;
>   
>   call p9(100);
>   ```
>
>   ```sql
>   -- 计算从1到n之间的偶数累加的值，n为传入的参数
>   -- 定义局部变量i作为计数器，定义局部变量sum作为和
>   -- 每循环一次对i进行+1，当i>n时跳出循环---leave xx
>   -- 如果当次i是奇数, 则直接进入下一次循环. --------> iterate xx
>   create procedure p10(in n int)
>   begin
>   	declare i int default 1;
>   	declare sum int default 0;
>   	
>   	sum_loop:loop 
>   		if i%2 = 1 then 
>     			set i := i+1;
>               iterate sum_loop;
>           end if;
>           set sum := sum+i;
>           set i := i+1;
>           
>           if i>n then 
>           	leave sum_loop;
>           end if;
>       end loop sum_loop;
>       select sum;
>   end;
>   
>   call p10(100);
>   ```
>
>   



>   ### 7、游标
>
>   **游标是用来存储查询结果集的数据类型 ,**
>
>   在存储过程和函数中可以**使用游标对结果集进行循环的处理**。
>
>   游标的使用包括游标的声明、OPEN、FETCH 和 CLOSE，其语法分别如
>
>   **声明游标**
>
>   ```sql
>   declare 游标名称 cursor for 查询语句;
>   ```
>
>   **打开游标**
>
>   ```sql
>   open 游标名称;
>   ```
>
>   **获取游标记录**
>
>   ```sql
>   fetch 游标名称 into 变量1,变量2....;
>   ```
>
>   **关闭游标**
>
>   ```sql
>   close 游标名称;
>   ```
>
>   #### 案例
>
>   -   根据传入的参数uage，来查询用户表tb_user中，
>   -   所有的用户年龄小于等于uage的用户姓名（name）和专业（profession），
>   -   并将用户的姓名和专业插入到所创建的一张新表(id,name,profession)中
>
>   ```sql
>   -- 逻辑:
>   -- A. 声明游标, 存储查询结果集
>   -- B. 准备: 创建表结构
>   -- C. 开启游标
>   -- D. 获取游标中的记录
>   -- E. 插入数据到新
>   -- F. 关闭游标
>   
>   create procedure p11(in uage int)
>   begin
>   	declare uname varchar(100);
>   	declare upro varchar(100);
>   	declare u_cursor cursor for select name,profession from tb_user where age <=uage;
>   	
>   	-- 声明条件处理程序 ： 当SQL语句执行抛出的状态码为02000时，将关闭游标u_cursor，并退出
>   	declare exit handler for SQLSTATE '02000' close u_cursor;
>   	# 或使用 declare exit handler for not found close u_cursor;
>   	
>   	drop table if exists tb_user_pro;
>   	
>   	create table if not exists tb_user_pro(
>           	id int primary key auto_increment,
>           	name varchar(100),
>           	profession varchar(100)
>       );
>       
>       open u_cursor;
>       
>       while true do
>       	fetch u_cursor into uname,upro;
>       	insert into tb_user_pro values (null, uname, upro);
>       end while;
>   	close u_cursor;
>   end;
>   
>   call p11(30);
>   ```
>
>   



## 4、存储函数

>   ### 1、介绍
>
>   **存储函数是有返回值的存储过程，存储函数的参数只能是IN类型的。具体语法**
>
>   ```sql
>   CREATE FUNCTION 存储函数名称 ([ 参数列表 ])RETURNS type [characteristic ...]BEGIN-- SQL语句RETURN ...;END
>   create function 存储函数名称( [参数列表] )
>   returns type [characteristic ...]
>   begin
>   	-- SQL语句
>   	return 值;
>   end;
>   ```
>
>   -   **characteristic**：
>       -   `determinstic`：相同的输入参数总是产生相同的结果
>       -   `no sql` ：不包含 SQL 语句。
>       -   `reads sql data`：包含读取数据的语句，但不包含写入数据的语局
>
>   #### 案例
>
>   **计算从1累加到n的值，n为传入的参数值**
>
>   ```sql
>   create function fun1(n int)
>   returns int deterministic
>   
>   begin
>   	declare total int default 0;
>   	
>   	while n>0 do
>   		set total := total + n;
>   		set n := n - 1;
>   	end while;
>   	return total;
>   end;
>   
>   select  fun1(50);
>   ```
>
>   **在mysql8.0版本中binlog默认是开启的，一旦开启了，**
>
>   **mysql就要求在定义存储过程时，需要指定characteristic特性，否则就会报错**
