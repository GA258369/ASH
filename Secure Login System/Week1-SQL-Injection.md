# 从零构建安全登录系统：Week 1 - 我亲手制造并利用了SQL注入

> 本系列记录我作为软件工程大三学生，如何通过Spring Boot实践构建安全的登录系统，并将开发与网络安全知识融合。

## 本周成果概览
- 建Spring Boot 3.4 + MySQL开发环境
- 实现有SQL注入漏洞的登录功能
- 亲手验证漏洞利用（使用`' OR '1'='1`成功绕过登录）
- 使用JdbcTemplate参数化查询修复漏洞

## 技术环境
- **后端框架**：Spring Boot 3.4.11
- **数据库**：MySQL + Spring Data JPA
- **构建工具**：Maven
- **Java版本**：21
- **工具**：IntelliJ IDEA, Postman, Burp Suite

## 漏洞制造：我写的"不安全"代码

在`LoginController`中，我最初使用字符串拼接构造SQL查询：

```java
@PostMapping("/login-vulnerable")
@ResponseBody
public String login(@RequestParam String username, @RequestParam String password) {
    Connection conn = null;
    Statement stmt = null;
    ResultSet rs = null;

    try {
        conn = DriverManager.getConnection(URL, USER, PASS);
        
        // 🔥 漏洞所在：直接字符串拼接
        String sql = "SELECT * FROM users WHERE username='" + username + 
                    "' AND password='" + password + "'";
        
        System.out.println("执行的 SQL: " + sql);  // 调试输出
        
        stmt = conn.createStatement();
        rs = stmt.executeQuery(sql);

        if (rs.next()) {
            return "<h1 style='color:green'>✅ 登录成功！欢迎，" + username + "</h1>";
        } else {
            return "<h1 style='color:red'>❌ 登录失败：用户名或密码错误</h1>";
        }
    } catch (Exception e) {
        e.printStackTrace();
        return "<h1 style='color:red'>❌ 数据库错误：" + e.getMessage() + "</h1>";
    } finally {
        closeResources(conn, stmt, rs);
    }
}
```

## SQL注入攻击验证

### 攻击payload：
```
用户名：' OR '1'='1
密码：任意值（如123）
```

## SQL注入成功截图：
![SQL注入攻击成功](./图片/SQL注入成功截图.png)


### 攻击原理分析：

**正常SQL：**
SELECT * FROM users WHERE username='admin' AND password='123456'

**被攻击后的SQL：**
SELECT * FROM users WHERE username='' OR '1'='1' AND password='123'
由于 '1'='1'`永远为真，整个WHERE条件成立，成功绕过身份验证！

### 控制台输出验证：
```
执行的 SQL: SELECT * FROM users WHERE username='' OR '1'='1' AND password='123'
```

## 安全修复：使用Spring JdbcTemplate

在AuthController中，我使用JdbcTemplate的参数化查询来修复漏洞：

```java
@RestController
public class AuthController {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * ✅ 修复后的登录接口：使用参数化查询防止SQL注入
     */
    @PostMapping("/login-safe")
    public String loginSafe(@RequestParam String username, @RequestParam String password) {
        try {
            // ✅ 关键修复：使用 ? 占位符
            String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
            return jdbcTemplate.query(sql, new Object[]{username, password}, rs -> {
                if (rs.next()) {
                    return "登录成功！欢迎：" + rs.getString("username");
                } else {
                    return "登录失败！用户名或密码错误。";
                }
            });
        } catch (Exception e) {
            return "数据库错误：" + e.getMessage();
        }
    }
}
```

## 项目配置亮点

我的`application.yaml`配置：
```yaml
server:
  port: 8081

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/login_demo?useSSL=false&serverTimezone=UTC
    username: root
    password: MySQL258369
```

前端`login.html`表单指向安全接口：
```html
<form action="/login-safe" method="post">
    <!-- 表单内容 -->
</form>
```

## 我的实战收获

1. 从理论到实践：课本上的SQL注入概念变得具体可见，`' OR '1'='1`不再只是理论
2. Spring Boot实战：第一次完整使用Spring Boot + JdbcTemplate开发Web应用
3. 安全意识建立：理解了为什么参数化查询是Web开发的基本要求
4. 调试技巧：通过控制台输出SQL语句，直观看到攻击原理

## 遇到的挑战与解决

- 环境配置：最初在application.properties中配置数据库连接失败，切换到YAML格式后解决
- 依赖冲突：注释掉了重复的MySQL依赖，保持pom.xml整洁
- 代码结构：从原始的JDBC连接升级到Spring JdbcTemplate，更符合企业级开发规范

*本系列完整代码已开源在[SecuredAuthLab](你的GitHub项目链接)仓库，欢迎Star和反馈！*
