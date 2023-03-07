  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // 1、 获取文件的存储路径
        String realPath = request.getServletContext().getRealPath(File.separator+"userfiles");
        File file = new File(realPath);
        if(!file.exists()){
            file.mkdirs();
            System.out.println("路径： "+realPath +" 创建成功!");
        }
 
        // 2、获取上传文件对象的集合
        Collection<Part> partList = request.getParts();
        if(partList.size() == 1){
            // 单个文件上传
            Part part = request.getPart("uploadfile");
            // 获取header 如： form-data; name="uploadfile"; filename="2018-08-11 开【华夏视讯网首发hxsxw.com】.mkv"
            String header = part.getHeader("content-disposition");
            // 获取文件名
            String fileName = header.split(";")[2].split("=")[1].replaceAll("\"", "");
            // 执行写入操作 --- 上传到指定的目录
            part.write(realPath+File.separator+fileName);
 
        }else{
            for (Part part : partList) {
                // 多个文件上传
                String header = part.getHeader("content-disposition");
                String fileName = getFileName(header);
                part.write(realPath+File.separator+fileName);
            }
        }
        request.setAttribute("message", "文件上传成功!");
        request.getRequestDispatcher("/WEB-INF/views/client/message.jsp").forward(request, response);
 
}
 
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }
 
    /**
    * 根据请求头解析出文件名
    * 请求头的格式：火狐和google浏览器下：form-data; name="file"; filename="snmp4j--api.zip"
    * IE浏览器下：form-data; name="file"; filename="E:\snmp4j--api.zip"
    * @param header 请求头
    * @return 文件名
    * @see https://www.cnblogs.com/xdp-gacl/p/4224960.html
    * @date 2018年8月12日 22:57:27
    */
    public String getFileName(String header) {
      /**
        * String[] tempArr1 = header.split(";");代码执行完之后，在不同的浏览器下，tempArr1数        组里面的内容稍有区别
        * 火狐或者google浏览器下：tempArr1={form-data,name="file",filename="snmp4j--api.zip"}
        * IE浏览器下：tempArr1={form-data,name="file",filename="E:\snmp4j--api.zip"}
        */
        String[] tempArr1 = header.split(";");
        /**
        *火狐或者google浏览器下：tempArr2={filename,"snmp4j--api.zip"}
        *IE浏览器下：tempArr2={filename,"E:\snmp4j--api.zip"}
        */
        String[] tempArr2 = tempArr1[2].split("=");
        //获取文件名，兼容各种浏览器的写法
        String fileName = tempArr2[1].substring(tempArr2[1].lastIndexOf("\\")+1).replaceAll("\"", "");
        return fileName;
    }
}