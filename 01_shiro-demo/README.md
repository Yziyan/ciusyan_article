# 简单安全管理框架——Shiro

## 写在前面
* 前前后后写了三篇文章，类容如下
* 文章地址
* [Shiro——基础篇](https://juejin.cn/post/7152092758051094536)
* [Shiro——进阶篇](https://juejin.cn/post/7153529501811474468)
* [Shiro——简单案例]()

## 一、初识Shiro

* 是Appache推出的安全管理框架
* 比起SpringSecurity更加**简单易用**
* 在Web项目中，一般用来作权限管理

### （1）核心功能

![img](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/026d15f841ab4616a459c3fdae67a1b6~tplv-k3u1fbpfcp-zoom-1.image)

* 认证
    * 有时候被称为登录验证，只有合法的用户才能登录进入系统
* 授权
    * 给对应的用户分配角色、以及权限
    * 确定谁有权限访问“什么资源”
* 会话管理
    * 管理特定于用户的会话，不局限与Web应用
* 密码学
    * 使用加密算法确保数据安全，同时任然易于使用



* 我这里会着重说明授权和认证



### （2）核心类型

* 网上很火的一张图

![image-20220916182555395](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/a6bfed2f661a4e5090a48a91d28d89fc~tplv-k3u1fbpfcp-zoom-1.image)



* Shiro核心的几个概念

```java
public static void main(String[] args) {

    // 1、安全管理器
    DefaultSecurityManager manager = new DefaultSecurityManager();
    // 2、设置安全管理器
    SecurityUtils.setSecurityManager(manager);
    // 3、设置数据源
    // ps：数据源 -> 这里是用 .ini 文件模拟一下
    IniRealm realm = new IniRealm("classpath:realm.ini");
    manager.setRealm(realm);

    // 4、模拟构建需要认证的主体
    Subject subject = SecurityUtils.getSubject();
    String username = "ciusyan";
    String password = "222";
    UsernamePasswordToken token = new UsernamePasswordToken(username, password);
    // 5、登录认证，不合法的用户，会抛出异常【如下所示】
    subject.login(token);
}
```



* 上面用到的`realm.ini`数据源

```ini
[users]
root = 111, admin
ciusyan = 222, guest

[roles]
admin = user:create, user:read, user:update, user:delete
guest = user:read
```



* `shiro`常见的几个异常

```java
public static void main(String[] args) {
    try {
        // 5、登录
        subject.login(token);
    } catch (UnknownAccountException e) {
        System.out.println("用户名不存在");
    } catch (IncorrectCredentialsException e) {
        System.out.println("密码不正确");
    } catch (AuthenticationException e) {
        System.out.println("认证失败~");
    }
}
```



## 二、自定义Realm

* 说这个问题之前，我们先来思考一下，为什么要自定义数据源 `Realm`呢？
* `Shiro`不是已经实现了好多Realm吗（如下图所示）

![image-20220917195234387](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/d6a608dfef0e459f88599c74f7519161~tplv-k3u1fbpfcp-zoom-1.image)

### （1）解答一

* 上面的那个例子，我们使用了 `.ini`文件，存放用户信息（用户名、密码、角色、权限）
* 可我们在真实的开发中，大概率是不会将用户信息放在`ini`文件里的
* 这不用我多说，你应该也知道。会将用户信息，放在数据库`DB`中存储
* 那这时候又有疑惑了啊，我上面放的图，`Shiro`默认不也实现了 `JDBC`吗
* 这不就又回到了我们的问题，为什么要自定义 `Realm`呢？

### （2）解答二

* 我们先来看一下，官方的描述信息

>Realm that allows authentication and authorization via JDBC calls. The default queries suggest a potential schema for retrieving the user's password for authentication, and querying for a user's roles and permissions. The default queries can be overridden by setting the query properties of the realm.
>
>If the default implementation of authentication and authorization cannot handle your schema, this class can be subclassed and the appropriate methods overridden. (usually doGetAuthenticationInfo(AuthenticationToken), getRoleNamesForUser(Connection, String), and/or getPermissions(Connection, String, Collection)


* `Shiro中JdbcRealm的sql`

![image-20220917200453622](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/ee43b31075de4a31a3a7645350cf885f~tplv-k3u1fbpfcp-zoom-1.image)

* 我们从上面的描述中，主要可以得出以下信息
    * 默认的实现，不太灵活。你程序的表名、和字段名，都得按默认的规范来
    * 如果不能满足我们的系统，我们可以自定义`Realm`
* 这一下，你应该知道，我们为什么要自定义数据源`Realm`了吧

### （3）如何实现

* 先实现一个简单的自定义数据源`Realm`
* 一样的，先模拟一下数据库

* 用户实体类

```java
public class User {
    private String username;
    private String password;
}
```

* 模拟数据库查询

```java
public class Dbs {
    public static User get(String username) {
        if ("ciusyan".equals(username)) {
            return new User("ciusyan", "222");
        }
        return null;
    }
}
```

#### 1、Step1

```java
public class CustomRealm extends AuthorizingRealm {

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        return null;
    }
}
```

* 在自定义的`Realm`中，直接继承类`AuthorizingRealm`

##### Q：为什么要继承这个类呢？

* 看这个类单词的拼写：授权 + 数据源
* 正如我们上面所说。你都到了授权的步骤了。那你肯定已经登录认证了
* 就好比你去学校读书，你都在找对应的班级了，难到你还没有进入学校吗？

* 况且官方的几个数据源`Realm`的默认实现，最终也是继承自`AuthorizingRealm`

![image-20220917202529768](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/70cf198514a74e6ba652b6b53ab2e892~tplv-k3u1fbpfcp-zoom-1.image)

#### 2、Step2

```java
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upTk = (UsernamePasswordToken) token;
        // 根据用户名，在数据库查询用户
        String username = (String) upTk.getPrincipal();
        User user = Dbs.get(username);
        // 判断是否有该用户
        if (user == null) return null;
        // 不需要验证密码
        return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
    }
```

* 实现`doGetAuthenticationInfo`方法【先认证】
* 当主体`subject`需要认证时，就会调用`doGetAuthenticationInfo`方法
* `@param token`是调用 `subject.login(token)`时，传入的token
* 一般情况下，需要在这里根据用户名查询用户的具体信息【用户名、密码等】

##### Q：为什么验证用户名和密码？

* 我们这里只是用用户名和密码举例，你可以进行其他操作。
* 你也可以验证其他的东西，比如自定义 `token`规则。也就是校验规则。我们之后在谈
* 这里先带大家看看两个`默认Token`中的方法，熟悉两个 `shiro`里的名词

```java
	private String username;
    private char[] password;

    public Object getPrincipal() { return getUsername(); }
    public Object getCredentials() { return getPassword(); }
```

* 用户名：`username` ---> `Principal`，所以之后我们简称`Principal`为用户名
* 密码：`password` ---> `Credentials`，所以之后我们简称`Credentials`为密码
* 因为它将其变成了返回 `Object`，方便类型转换

##### Q：为什么只验证用户名而不验证密码呢？

* 因为在`Shiro`里面，这个验证密码的操作
* 有专门的部分来负责，更为专业。耦合性更低
* 比如我们可以先看看，刚刚我们使用过的 `.ini`，它里面是如何实现的

```java
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        SimpleAccount account = getUser(upToken.getUsername());
		
        if (account != null) {
            if (account.isLocked()) { }
            if (account.isCredentialsExpired()) { }
        }
        return account;
    }
```

* 我们可以看到，它这里的做法是，根据查询的用户信息`account`，检查一下有没有被锁定，有没有过期。
* 就直接将 `account`返回了，我们也没有看到，他这里有验证密码吧
* 那你就有疑惑了，那它是如何验证的呢？

##### `Credentials`的验证

* 先看主要步骤

```java
// step1
return new SimpleAuthenticationInfo(user.getUsername(), user.getPassword(), getName());
// setp2
assertCredentialsMatch(token, info);
// step3
if (!cm.doCredentialsMatch(token, info)) { ... }
// step4
public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
    Object tokenCredentials = getCredentials(token);
    Object accountCredentials = getCredentials(info);
    return equals(tokenCredentials, accountCredentials);
}
```



* 当我们将查询的`account`信息直接返回之后。
* `shiro`会去调用利用`Realm`去调用`CredentialsMatcher中的方法`
* 根据这个名字，我们就可以知道。这是密码匹配器。用于校验密码的
* 默认的实现。直接`equals(tokenCredentials, accountCredentials)`
* 将登录的`token`时的密码与返回 `account`中的密码相比



##### 认证流程

* 密码认证通过之后，我们的认证流程就走完了，那么，我们一起来总结一下其中的过程



![image-20220918171913385](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/231c56cbb1684b3eac24ac743aabcff5~tplv-k3u1fbpfcp-zoom-1.image)



* 从图中，我们可以看到。登录时传入了一个 `token`【我们这称为用户信息令牌】
* 这个令牌会一直呆到调用完`doGetAuthenticationInfo`
* 而图中出现的`info`信息，是调用完`doGetAuthenticationInfo`
* 返回了 `account`后，才进行传递的
* 这也证实了我们上面所说的，来到这个安全系统
* 都是经过管理员`securityManager`之后的，`subject.login()`也是一样



* 用文字描述一下这个流程图的关键步骤

```java
/*

认证流程
1、Subject.login(token)
2、SecurityManager -> Authenticator -> Realm【AuthorizingRealm】
3、info = AuthorizingRealm.doGetAuthenticationInfo(token)。根据封装的token令牌，去查询对应的用户信息【如去数据库查询】
4、CredentialsMatcher.doCredentialsMatch(token, info)：判断token与info中的Credentials是否正确

*/
```



#### 3、Step3

* 来到这里，你的认证肯定是已经通过了。既然认证通过了
* 那我们想要获取该用户的权限信息、角色信息。又该如何获取权限信息呢？

```java
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 拿到刚刚已经认证通过的用户名
        String username = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        
        // 【去查询角色信息】添加角色信息
        List<String> roles = Dbs.listRoles(username);
        if (roles != null) {
            info.addRoles(roles);
        }

        // 【去查询权限信息】添加权限信息
        List<String> permissions = Dbs.listPermissions(username);
        if (permissions != null) {
            info.addStringPermissions(permissions);
        }
        return info;
    }
```



* 模拟去数据库查询用户的【角色信息、权限信息】

```java
    // 角色
    public static List<String> listRoles(String username) {
        if ("ciusyan".equals(username)) {
            return List.of("admin", "normal");
        }
        return null;
    }

    // 权限
    public static List<String> listPermissions(String username) {
        if ("ciusyan".equals(username)) {
            return List.of("user:create", "user:read", "user:update");
        }
        return null;
    }
```



* 当主体（subject）想要去鉴权的时候，他就会来到授权的方法`doGetAuthorizationInfo`
* 例如

```java
            System.out.println("【权限】user:create -> " + subject.isPermitted("user:create"));
            System.out.println("【权限】user:read -> " + subject.isPermitted("user:read"));
            System.out.println("【权限】user:delete -> " + subject.isPermitted("user:delete"));
            System.out.println("【角色】admin -> " + subject.hasRole("admin"));
            System.out.println("【角色】normal -> " + subject.hasRole("normal"));
            System.out.println("【角色】teacher -> " + subject.hasRole("teacher"));
```



![image-20220926093755295](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/dabf6a54373042cdaa5bdf96bb1fae37~tplv-k3u1fbpfcp-zoom-1.image)



* 如上图所示，当主体 `subject`去调用`hasRole、isPermitted`等方法时
* `Shiro`就会去调用授权方法，检验用户的权限
* 可以看到，`ciusyan`这个用户只有`admin、normal`这两个角色
* 有`user:create、user:read、user:update`三种权限
* 到这里，相信你应该知道，打印结果为什么是这样了。



##### 鉴权流程

![image-20220926101644181](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/993bc36b954f456fa41e2af1c180858f~tplv-k3u1fbpfcp-zoom-1.image)



* 注：我这里说的是去验证权限【验证角色同理】

* 当调用鉴权相关的方法时，主体又会去找到管理员`securityManager`
* 管理员又会去找授权器`Authorizer`
* 然后授权器为了拿到权限信息，会去调用`doGetAuthorizationInfo`方法
* 这时候就来到了我们自定义`Realm`的授权方法，在这里看看，我们给他授予了什么权限
* 获取完所有权限信息之后，会去遍历刚刚获取到的权限
* 与传进来需要去验证的权限比对



* 用文字描述一下这个流程图的关键步骤

```java
/*

鉴权流程【验证角色、权限的流程】
1、Subject.isPermitted(permission)、Subject.hasRole(role)
2、SecurityManager -> Authorizer -> Realm【AuthorizingRealm】
3、info = AuthorizingRealm.doGetAuthorizationInfo(principals 的集合)。根据principal，去查询对应的角色、权限信息【如去数据库查询】
4、根据返回的info信息，判断权限、角色是否正确

*/
```

## 写在后面

### （1）读后思考

* 为什么需要自定义`Realm`?
* `Shiro`中还有什么部分可以自定义？为什么需要自定义这些部分？
* 认证和鉴权的大致流程？


### （2）下篇预告

* **Shiro进阶指南**

* 将`Shiro`集成到Web项目【Spring Boot】
* 为什么要自定义`balabala...`


# 简单安全管理框架——Shiro进阶

### （2）读前须知
1. 本文是承接着上一篇Shiro的文章
    * 推荐可以先看看 [Shiro篇①——基础篇](https://juejin.cn/post/7152092758051094536)
2. 上一篇Shiro的文章，操作都是对`JavaSE`的项目而言的。可我们怎么将Shiro集成到Web项目
3. 并且定制化配置，自定义的内容如下
    * 过滤器（Filter）、数据源（Realm）
    * 校验规则（Token）、密码匹配规则（CredentialsMatcher）


## 一、目标实现

* 现在前后端分离的项目中，有着各种各样的会话管理方案。而今较为常用的有**Token + xxx**
* 我们想要用`Shiro`做认证授权，刚好可以和 `Token`结合起来，

1. 登录接口：返回**Token令牌**
2. 其他未放行接口：携带登录时返回的**Token**，需验证：
    * 请求是否携带**Token**
    * **Token**是否有效
    * 经过`Shiro`认证
    * 经过`Shiro`授权



## 二、为什么要自定义

* 在具体配置之前，我们先来聊聊，为什么要定制化`Shiro`
* 如果你耐心看完了上一篇文章的`认证流程与授权流程`，应该会发现几个问题
    * 登录传入的默认令牌`Token`，太过于局限
    * 默认数据源`Realm`太死板
    * 密码`Credentials`校验规则太随意
    * 需要手动去调用认证方法
    * ....
* 那我们就来说说具体的意义吧


### （1）自定义`Realm`

* 相信现在说到这个，你已经明白为什么要自定义数据源了
* 最主要的就是去重写两个方法`doGetAuthenticationInfo | doGetAuthorizationInfo`
* 一个去获取用户信息，一个去获取角色权限信息
* 如果还不清楚，可以回看一下上一篇的内容


### （2）自定义`Token`

* 在Web项目中，通常会使用 `Token + ...` 进行会话管理
* 通常情况下，用户登录成功后会返回一个`用户身份令牌（Token）`
* 用户访问其他功能时，都需要携带上这个令牌，代表自己是一个合法用户
* 用户拿到了这个令牌，就相当于登录成功了，换句话说就是用户名和密码已经校验成功了
* 这时就不需要再使用`Shiro`去验证用户名和密码了（冗余操作）
* 那问题又来了啊，使用`Shiro`应该校验什么呢？
* 答案很简单，校验用户身份令牌`Token`即可
* `Token`代表用户身份，那么证明`Token`是有效的之后，不就可以知道用户是有效了的呐！
* 如果我们想要利用类似这样的方式去进行认证，那么以前的简单比对用户名和密码，就不能满足我们的需求了
* 所以我们也需要自定义`校验规则Token`，使我们的校验更加灵活



### （3）自定义`CredentialsMatcher`

* 如果你看完了上篇文章的认证流程，你就会知道，`Shiro`会在何时去进行`密码匹配`
* 如果你看完了`为什么要自定义Token`，你应该也可以推测出，为什么要自定义`密码匹配规则`
* （可是哪里会有那么多的如果）
* 其实就是为了按我们自己的规则进行校验，甚至是**直接放行，不用校验**



### （4）自定义`Filter`

* 其实自定义`过滤器Filter`，完全可以不写在这篇文章里
* 因为`Filter`是独立出来的一种技术，可以**完全不依赖**于`Shiro`
* 这时候你可能会骂我了：“什么小破文💩💩💩...balabala....”
* 先别急，听我细细道来，耐心看下去
* 一般情况下，前后端分离的Web项目，会有很多接口
* 而这些接口，有的是不需要登录就可以访问的、需要登录才能访问的、需要有特定权限才能访问的
* 所以，我们怎么去认证？何时去认证？何时去加载权限？
* 不可能每个接口，都做一遍判断吧？
* 这时候，聪明的你大概率会想到 `过滤器、拦截器之类的词`
* 其实都可以实现，而我们这里选择使用过滤器`Filter`，可以和`Shiro`很好的结合起来
* 所以我们总结一下为什么要自定义过滤器：
* 为了过滤请求、可以检验用户是否携带`身份令牌Token`，`Token`是否过期，去加载用户的角色，去加载用户的权限...
* 使用过滤器，可以做到书写一次验证代码，所有接口适用



## 三、具体实现

* 说完了为什么要定制化`Shiro`，那我们就来定制化并且使用一下它吧~



### Step0【导入依赖】



```java
        <!-- 权限控制 -->
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring-boot-web-starter</artifactId>
            <version>${shiro.version}</version>
        </dependency>
```

* 这一步就不过多的描述了



### Step1【Shiro 配置类】

* 我们在使用 `Shiro` 之前，得先配置一下`Shiro`
* 就好比你去读书之前，总要填写很多信息，才能进入学校
* 那我们具体配置什么呢？在具体配置之前，不妨先和我一起看看，我们想要使用`Shiro`来做什么



![image-20221008173049018](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/a1e2d3b96f964cfc9d72c22d04afdbd8~tplv-k3u1fbpfcp-zoom-1.image)

* 如上图所示，我们就想要做到这种效果。
* 请求从客户端发送过来，通过`Shiro`中断一下
* 1、决定我们的请求是否能调用controller【认证】
* 2、到达了controller，是否需要去鉴权【授权】
* 所以，我们要去配置一个 `Shiro过滤的工厂对象`，并且将其放入`Spring` 的 `IoC`容器中



```java

@Bean
public ShiroFilterFactoryBean shiroFilterFactoryBean(Realm realm) { }
```



* 在这个方法里，我们需要：
    * 告诉`Shiro`如何进行拦截
    * 拦截那些`URL`
    * 每个`URL`需要进行那些 `filter`
* 如果你看完了之前的内容，你肯定知道`Shiro`是通过安全管理器来管理自己的一些列流程的
* 那我们就需要告诉`ShiroFilterFactoryBean`，我们的**安全管理器**
* 而设置**安全管理器**的时候，我们又需要告诉安全管理器，我们需要使用什么**数据源**
* 而设置**数据源**的时候，我们又需要告诉数据源。使用什么**校验规则、密码匹配规则**

![image-20221008175949144](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/4bf2e3b347c8401bb88a3eb4ffb54029~tplv-k3u1fbpfcp-zoom-1.image)



* 如上图所示，聪明的你，应该能猜到，我们 **Setp2、3、4**要做什么了吧~
* `shiroFilterFactoryBean()方法`详细实现在下面奉上，因为我们要先自定义...💄



### Step2【自定义Realm】

```java

public class TokenRealm extends AuthorizingRealm {

    /**
     * 告诉此Realm需要使用什么密码匹配规则
     * @param matcher：自定义的密码匹配规则
     */
    public TokenRealm(TokenMatcher matcher) {
        super(matcher);
    }
    
    /**
     * 用于认证器所需要的Token
     * @param token : 认证器的那个token
     * @return ：是否符合要求
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof Token;
    }

    /**
     * 授权器
     * @param principals ：认证器认证成功传过来的shiro信息【Shiro的用户名和密码】
     * @return 该shiro用户所拥有的权限和角色信息
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 拿到当前登录用户的token
        String token = (String) principals.getPrimaryPrincipal();
        
 		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        
        // TODO：1、根据token查找用户的角色、权限
        
        // TODO：2、添加角色
        info.addRole(/* 角色 */);

        // TODO：3、添加权限
        info.addStringPermission(/* 权限 */);
        
        return info;
    }

    /**
     * 认证器 【SecurityUtils.getSubject().login(new Token(token)) 会触发此认证器】
     * @param authenticationToken：token
     * @return ：认证成功传出去的 信息【Shiro的用户名和密码】
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String tk = ((Token) token).getToken();
        return new SimpleAuthenticationInfo(tk, tk, getName());
    }
}
```



* 相信你现在看到`doGetAuthenticationInfo、doGetAuthorizationInfo`方法，应该很清晰
* 但是你可能也会有疑问，为什么我在`doGetAuthenticationInfo`方法里，直接返回了需要认证时传入的 token，并没有去验证用户名啥的
* 这是为什么呢？我们暂且称为**疑惑一**，在解决疑惑一之前，我先说一下为什么要重写 `supports()方法`

#### supports()方法

* 这个方法拿来干嘛的呢？为什么要重写该方法呢？
* 看整个方法的构造和方法名

```java
boolean supports(AuthenticationToken token);
```

* 你大概能猜到，这是用来查看`Realm`支持什么 `Token`校验令牌的



![image-20221010124316780](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/0456ec25d1ce4d52a45cf65b0623ac46~tplv-k3u1fbpfcp-zoom-1.image)



* 从上图，我们可以知道，`Shiro`在去 认证`(Authentication)` 之前，会先检查一下，我们使用的数据源`Realm`，它的`Token`是否支持使用，如果不支持就会抛出异常【Realm不能使用此种Token】

```java

String msg = "Realm [" + realm + "] does not support authentication token [" + token + "].  Please ensure that the appropriate Realm implementation is configured correctly or that the realm accepts AuthenticationTokens of this type.";
            throw new UnsupportedTokenException(msg);
```

* 而我们既然要**自定义**实现 `Token`，那么我们可以限定传入`Token`的类型，是我们自定义的Token
* 当你知道这些，你也就知道，`supports()`方法是用来做什么的了



### Step3【自定义CredentialsMatcher、Token】



#### 1、自定义Token

```java

@Data
public class Token implements AuthenticationToken {
    private final String token;

    public Token(String token) {
        this.token = token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
```

* 继承 `AuthenticationToken`即可
* 很简单，贴合我们的验证方式。登录时返回一个`Token令牌`，访问其他接口时，携带上登录时的`Token令牌`
* 我们就可以使用这个 `Token`去认证、授权 ...
* 如果你看过了上一篇`Shiro`的文章，那么你看到`getPrincipal()、getCredentials()`方法，应该知道是什么
* 而它们的返回值，都是传入的 `Token`，这是为什么呢？这里我们称为**疑惑二**
* 耐心的你要是读到了这里，估计都骂我"balabala..."了，没关系，我们再看自定义`CredentialsMatcher`



#### 2、自定义CredentialsMatcher

```java

public class TokenMatcher implements CredentialsMatcher {
    @Override
    public boolean doCredentialsMatch(AuthenticationToken authenticationToken, AuthenticationInfo authenticationInfo) {
        return true;
    }
}
```

* 如果你看完了上一篇文章的认证流程，那么你应该知道为什么要继承`CredentialsMatcher`，重写`doCredentialsMatch()`方法了吧
* 而我们这里的实现更简单，直接返回 `true`，代表`密码Credentials`匹配成功
* 那你肯定会有疑问了：**疑问三**，这里不是要验证`密码Credentials`吗？为什么直接放行，让其密码认证通过？



#### 3、Q：

* 写到这里，我们先来回看一下上疑问
* 疑问一：在`doGetAuthenticationInfo()`方法里，没有验证用户名，直接将传入的`Token`构建成`account`返回了
* 疑问二：在自定义`Token`的时候，重写`getPrincipal()、getCredentials()`实现，为什么都返回传入的 `token`
* 疑惑三：在自定义`CredentialsMatcher`时，为什么没有直接放行

#### 4、A：

* 如果有这些疑问，我们画一张图回顾一下，我们想要实现的目标的流程

![image-20221010154930599](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/d29a5c9486504bf0bd67e7207b0de406~tplv-k3u1fbpfcp-zoom-1.image)



* 从这张图，我们可以看到，服务器返回 `Token令牌` 给客户端，是在登录之后
* 并且是成功登录之后，如果有用户名 or 密码错误，服务器根本不会返回`Token令牌`给客户端
* 那么，你也就知道，在`Shiro`这里，为什么不需要验证用户名、密码了吧
* 而疑问二，重写实现，主要是因为我们自定义的 `Token`不需要使用用户名和密码。只需要维护一个自定义的 `token 字符串`，所以直接将其字符串返回【后面也不一定会用到，只是必须实现该抽象方法，在需要使用的时候，更方便的做类型转换罢了】
* PS：回看一下为什么要自定义`Shiro`，你会发现，其实我们已经知道这几个疑问了，嘿嘿👷👷👷~



### Step4【自定义Filter】

```java

public class TokenFilter extends AccessControlFilter {
    /**
     * 当请求被TokenFilter拦截时，就会调用这个方法
     * 可以在这个方法中做初步判断
     *
     * 如果返回true：允许访问。可以进入下一个链条调用（比如Filter、拦截器、控制器等）
     * 如果返回false：不允许访问。会进入下面的onAccessDenied方法，不会进入下一个链条调用
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object o) throws Exception {
        return false;
    }

    /**
     * 当isAccessAllowed返回false时，就会调用这个方法
     * 在这个方法中进行token的校验
     *
     * 如果返回true：允许访问。可以进入下一个链条调用（比如Filter、拦截器、控制器等）
     * 如果返回false：不允许访问。
     */
    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
       
        // 取出Token
        String token = request.getHeader("Token");

        // 如果没有Token
        if (token == null) {
            throw new InvalidParameterException("没有Token，请登录");
        }

        // 如果Token过期了
        if ( /* 通过 token 取不出用户信息 */ ) {
            throw new InvalidParameterException("Token已过期，请重新登录");
        }

        // 去认证且授权（进入Realm）
        // 这里调用login，并不是“登录”的意思，是为了触发Realm的相应方法去加载用户的角色、权限信息，以便鉴权
        SecurityUtils.getSubject().login(new Token(token));
        return true;
    }
}
```



* 继承`Shiro提供的AccessControlFilter`（最终也是继承 `servelet的 filter`）
* 实现`isAccessAllowed()、onAccessDenied()`两个方法
* **!!!调用**`SecurityUtils.getSubject().login(new Token(token));`
* 这里是去走通用`Shiro认证授权流程`
* 相应的描述，我写在了注释中，画一幅图，来说明一下这个流程

![image-20221010204902949](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/a02105cc15384114881fcabbdeeafc34~tplv-k3u1fbpfcp-zoom-1.image)

* 举一个例子理解一下：
    * 1、客户端对服务器发起恋爱请求😵🐶🐶
    * 2、`isAccessAllowed()`方法对客户端进行初步判断
    * 3、如果服务器对客户端也很有感觉，那么直接同意了他的恋爱请求，将其放行到下一链条
    * 4、如果服务器对客户端感觉不是那么好，但是又不想直接拒绝，还想再观察观察。将其放入到`onAccessDenied()`方法中
    * 5、经过一系列严格检验，发现客户端其实还不错，同意他的恋爱请求，将其放行到下一链条
    * 6、严格检验后发现客户端不太合适，那就直接pass了，没有反转的余地



## 四、具体实现总结



### （1）流程

* 跟着我一起走完了定制化`Shiro`的**Step1、2 ...**
* 相信你已经有了不少的收获，那我们在来总结一下这几个步骤吧~
* 这一套流程，我们已经过了一遍，如果还没有走通，那么就还差几张图~🖼️🖼️
* 注：我们这里并没有谈到Shiro的`缓存管理器：CacheManager`



![image-20221011083306709](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/3e363398846348058d78a5b607e0a43f~tplv-k3u1fbpfcp-zoom-1.image)

* 上图是一个**不需要**权限or角色即可访问的接口，一个**认证**的流程
* 下图是一个**需要**权限or角色才能访问的接口，一个**认证和鉴权**的流程

![image-20221011085033180](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/5ca2cc706739468b8c482ed047b67ad7~tplv-k3u1fbpfcp-zoom-1.image)

* 下图是访问一个需要权限or角色的接口的执行流程

![image-20221010215443083](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/80cb413ac5134135be8a1f2aec3b9e8f~tplv-k3u1fbpfcp-zoom-1.image)



### （2）额外补充【怎么利用token查询用户的角色、权限信息】



* 如果你前面的流程没有什么问题，那你可能有一个疑惑，这个从登录开始就一直维护的`token`，是如何代表用户信息的呢？
* 我这里说两种常用的方案

#### 1、Token + Cache

* 这种方案，顾名思义，在登录的时候，生成一串`字符串（Token）`
* 利用这个 `Token`作为 `key` 将其信息**缓存**起来
* 在之后的请求中，使用这个 `Token`作为`key`，从缓存中取出当初存储的信息
* 而将缓存放在哪里呢？
    * 服务器内存、JVM内存、Redis数据库
    * 甚至你还可以存储在Mysql这种关系型数据库中（不推荐）
* 其实放在哪里都可以，具体的得看业务需求，业务体量



#### 2、Json Web Token [JWT](https://jwt.io/introduction)

* 这种方案也很常用，在登录的时候，将用户信息，利用一定加密、签名算法
* 生成一串，有一定格式的`字符串(Json Web Token)`
* 在之后的请求中，使用当初生成这个`JWT字符串`的规则，逆向解析出用户的信息



### （3）再谈`shiroFilterFactoryBean()`方法

* 当我们定制化完成后，我们还需要将其添加到`Shiro的配置里`，并且放入`IoC`中。
* 先奉上刚刚欠下的常用配置

![image-20221011103741183](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/9a8597420e3e424abe364b25c17e636c~tplv-k3u1fbpfcp-zoom-1.image)



* 下面是上图中标序号的注意事项

    * **① 方法名字必须为`shiroFilterFactoryBean`**
    * **② 安全管理器的类型为 `DefaultWebSecurityManager`**
    * **③ 使用的`Realm`必须放入 `Spring IoC容器`中**
    * **④ 若有自定义的`Filter` 必须配置，key 为下面URI 使用的名称，可以配置多个**
    * **⑤ 添加URI映射的时候，必须保证遍历的时候是有序的。所以使用`LinkedHashMap`**
    * **⑥ 配置的URI越靠前，优先级越高，并且可以同时使用多个。使用自己的 `Filter`，名字为当初设置时的key**



* 除了使用自定义的过滤器，`Shiro`还提供了很多默认的[DefaultFilter](https://shiro.apache.org/web.html#default_filters)

![image-20221011105351555](https://p3-juejin.byteimg.com/tos-cn-i-k3u1fbpfcp/6a9afe844ecf42c59cef2c38ed0ca67b~tplv-k3u1fbpfcp-zoom-1.image)

* 具体使用请查看文档，比较常用的有 `anno`匿名filter【相当于直接放行】
* 下面是一个配置的模板

```java

	/**
     * Shiro过滤器工厂
     * @param realm：Shiro数据源
     * @param properties：项目配置
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(Realm realm, WorkBoardProperties properties) {
        ShiroFilterFactoryBean filterBean = new ShiroFilterFactoryBean();
        // 安全管理器【并且告诉使用上面realm】
        filterBean.setSecurityManager(new DefaultWebSecurityManager(realm));
        
        // 添加自定义 Filter
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("token", new TokenFilter());
        filterBean.setFilters(filterMap);

        // 添加 URI 映射
        Map<String, String> uriMap = new LinkedHashMap<>();

        // 放行登录&注册接口&发送验证码&忘记密码
        uriMap.put("/admin/users/login", "anon");
        uriMap.put("/admin/users/register", "anon");
        uriMap.put("/admin/users/sendEmail", "anon");
        uriMap.put("/admin/users/sendTest", "anon");
        uriMap.put("/wx/users/getSessionId", "anon");
        uriMap.put("/admin/users/forgotPwd", "anon");
        uriMap.put("/admin/users/captcha", "anon");

        // 放行Swagger文档
        uriMap.put("/swagger**/**", "anon");
        uriMap.put("/v3/api-docs/**", "anon");

        // 放行获取静态资源的URI
        uriMap.put("/" + properties.getUpload().getUploadPath() + "**", "anon");

        // 其他 URI 使用自定义的 filter
        uriMap.put("/**", "token");

        filterBean.setFilterChainDefinitionMap(uriMap);
        return filterBean;
    }
```
