import tornado.ioloop
import tornado.web
import tornado.template as template

# 创建一个自定义的 RequestHandler 类
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        name = self.get_query_argument('name', 'John Doe')
        # name = "{{2+2}}"
        print(name)
        self.write(template.Template(name).generate(name=name))
        # loader = tornado.template.Loader("templates")
        # self.write(loader.load("index.html").generate(name=name))



# 创建一个 Tornado 应用
def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
    ])

# 启动 Tornado 服务器
if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()