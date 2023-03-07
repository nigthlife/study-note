private static StringBuffer listTojson(StringBuffer buffer,List list) throws IllegalArgumentException, IllegalAccessException{
        
    //遍历传过来的list数组
    for (Object object : list) {
            
        //判断遍历出的值是否为空
        if (object == null) {
            buffer.append(",");    
        }
        else{
                
            Class<? extends Object> class1 = object.getClass();
            String simpleName = class1.getSimpleName();
                
            if(simpleName.equals("String")){
                    
                buffer.append("\""+object.toString()+"\",");
            }
            else if(simpleName.equals("Boolean")||simpleName.equals("Integer")||simpleName.equals("Double")||simpleName.equals("Float")||simpleName.equals("Long")){
                    
                buffer.append(""+object.toString()+",");
            }
            else if(simpleName.equals("Date")){
                Date date = (Date) object;
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
                String simdate = simpleDateFormat.format(date);
                buffer.append(""+simdate+",");
            }
            // 如果为一个对象集合
            else{

                // 获取集合的类加载器对象    
                Class<? extends Object> class2 = object.getClass();
                Field[] fields = class2.getDeclaredFields();
                Field.setAccessible(fields, true);
                buffer.append("{");

                //遍历对象中的所有字段获取字段值和字段名称拼成json字符串
                for (Field field : fields) {
                        
                    Object fieldobj = field.get(object);
                    String fieldName = field.getType().getSimpleName();
                        
                    if(fieldobj == null){
                            
                        if(fieldName.equals("String"))
                        {
                            buffer.append("\""+field.getName()+"\":\"\",");
                        }
                        
                        else{
                            buffer.append("\""+field.getName()+"\":null,");
                        }
                            
                    }
                        
                    else{
                            
                        String fsimpleName = fieldobj.getClass().getSimpleName();
                            
                        if(fsimpleName.equals("String")){
                                
                            buffer.append("\""+field.getName()+"\":\""+field.get(object)+"\",");
                        }
                        else if(fsimpleName.equals("Boolean")||fsimpleName.equals("Integer")||fsimpleName.equals("Double")||fsimpleName.equals("Float")||fsimpleName.equals("Long")){
                                
                            buffer.append("\""+field.getName()+"\":"+field.get(object)+",");
                        }
                        else if(fsimpleName.equals("Date")){
                            
                            Date date = (Date) object;
                            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
                            String simdate = simpleDateFormat.format(date);
                            buffer.append("\""+field.getName()+"\":"+simdate+",");
                        }
                        else{
                            
                            buffer = beanTojson(fieldobj, buffer).append(",");
                        }
                    }
                        
                }
                    
                buffer =  new StringBuffer(""+buffer.substring(0,buffer.length()-1)+"");
                buffer.append("},");
            }
            }
            
        }
        
        buffer =  new StringBuffer(""+buffer.substring(0,buffer.length()-1)+"");
        buffer.append("]");
        
        return buffer;
    }