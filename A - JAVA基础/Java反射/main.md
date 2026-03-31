## 基本概念

**反射**（Reflection）是 Java 中的一种机制，它允许程序在运行时动态地访问类的结构和行为，包括类、方法、字段、构造函数等，从而实现动态调用和操作。

通过反射，程序不需要在编译时就确定使用的类、方法或字段，而是在运行时动态地加载和使用它们。反射广泛用于框架设计、工具开发和动态操作等场景。

OK，反射的概念可能比较抽象，让我们来举个例子。

## 应用场景

在许多产品中，需要支持用户通过插件扩展功能，而插件的具体实现通常是在运行时由用户提供的。这种场景下，程序在设计时并不确定会加载哪些插件类或调用哪些方法，而是在运行时动态加载插件类，并通过反射调用相关方法。

以IDEA插件举例

1. **插件以 JAR 包形式存在**
   每个插件是一个 JAR 包，包含具体实现类和 `plugin.xml` 配置文件，用于描述插件的入口类。
2. **运行时动态加载插件**
   IDEA 使用 **反射** 配合 **类加载器** 动态加载插件入口类，实例化插件对象并调用其方法。

## **核心概念**

1. **运行时动态获取类型信息**
   - 通过反射，可以获取某个类的完整信息，例如其类名、父类、接口、构造函数、方法和字段等。
2. **动态操作对象的属性和方法**
   - 即使在编译期并不知道具体的类和方法名，反射也可以在运行时访问和调用这些元素。
3. **绕过访问限制**
   - 通过反射，可以访问私有字段和方法（通过设置 `AccessibleObject.setAccessible(true)`），这为框架设计带来灵活性的同时，也可能引入安全隐患。

## **反射的实现方式**

Java 反射主要依赖于 `java.lang.reflect` 包中的类，以下是常用的反射工具类：

- **`Class`**：表示类的字节码对象，可以用来加载类、获取类的信息。
- **`Field`**：表示类的字段，可以获取和设置字段的值。
- **`Method`**：表示类的方法，可以动态调用方法。
- **`Constructor`**：表示类的构造函数，可以通过它创建对象。

## Class

在 Java 中，`Class` 类和反射密切相关。反射机制允许程序在运行时动态地查询、访问和操作类的元数据，而 `Class` 类是进行反射操作的基础。可以通过 `Class` 类获取一个类的详细信息，甚至可以通过反射实例化类、调用方法、获取字段等。

`Class` 类是 Java 中每个类的模板，Java 中的每个类（包括用户定义的类）都有一个对应的 `Class` 对象，它是类元数据的载体。

每个类的定义都可以通过 `Class` 对象来引用，通过 `Class` 对象可以获取类的结构信息，比如：

* 类名
* 类的构造方法
* 类的字段和方法
* 类的父类和接口

## 示例类

```java
class Person {
    private String name;
    private int age;

    // 构造方法
    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    // 方法
    public void introduce() {
        System.out.println("My name is " + name + " and I am " + age + " years old.");
    }

    // 获取年龄
    public int getAge() {
        return age;
    }
}
```

## 获取Class对象
                                                                                                                                                                                
  有四种方法可以获取到Class对象

  方式1

```java
  public static void main(String[] args) throws Exception {
      // 获取 Person 类的 Class 对象
      Class<Person> clazz = Person.class;
  }
```

  在 Java 中，Person.class 是直接通过类字面量（Class Literal）获得 Person 类的 Class 对象。这个 Class 对象是 Java 类型系统中表示 Person 类的对象。

  - Person.class 表示 Person 类本身（而非 Person 的实例）。
  - Person.class 获取的是一个 Class<Person> 类型的对象，它表示 Person 类的元数据。
  - 在这里，Person.class 的类型是 Class<Person>，这意味着它是一个 Class 类型对象，且其泛型参数为 Person 类本身。

  方式2
```java
  public static void main(String[] args) throws Exception {
      // 通过实例获取 Person 类的 Class 对象
      Person person = new Person();
      Class<? extends Person> clazz = person.getClass();
  }
```
  person.getClass() 调用的是 Object 类的 getClass() 方法，返回的是该实例的运行时类型的 Class 对象。

  - 返回类型是 Class<? extends Person> 而非 Class<Person>，是因为 person 在运行时可能是 Person 的某个子类实例，使用 ? extends Person 更准确地表达了这一点。
  - 注意与方式1的区别：方式1在编译期就确定了类型，方式2反映的是运行时的实际类型，当 person 是子类实例时两者会不同。

  方式3
当你知道一个 class 的完整类名，可以通过静态方法 Class.forName() 获取：
```java
  public static void main(String[] args) throws Exception {
      Class<?> cls = Class.forName("com.test.Person");
  }
```
  - 类名必须是完整的全限定名（包含包名）。
  - 该方法会触发类的初始化，如果类不存在会抛出 ClassNotFoundException。
  - 由于类名是字符串，编译期无法确定具体类型，因此返回类型为 Class<?>。

  方式4

  通过类加载器获取：

```java
  public static void main(String[] args) throws Exception {
      Class<?> clazz = ClassLoader.getSystemClassLoader().loadClass("com.test.Person");
  }
```

  - 与 Class.forName() 类似，同样需要完整的全限定类名。
  - 两者的关键区别：Class.forName() 默认会触发类的初始化（执行静态代码块），而 ClassLoader.loadClass() 只加载类但不会触发初始化。

## 获取构造方法

通过Class实例获取Constructor的方法如下：

- `getConstructor(Class...)`：获取某个`public`的`Constructor`；
- `getDeclaredConstructor(Class...)`：获取某个`Constructor`；
- `getConstructors()`：获取所有`public`的`Constructor`；
- `getDeclaredConstructors()`：获取所有`Constructor`。

调用非`public`的`Constructor`时，必须首先通过`setAccessible(true)`设置允许访问。`setAccessible(true)`可能会失败。

```java
public static void main(String[] args) throws Exception {
    // 获取 Person 类的 Class 对象
    Class<?> clazz = Person.class;
    // 获取public类型的所有构造方法
    Constructor<?>[] constructors = clazz.getConstructors();
    // 获取指定参数的Constructor
    Constructor<Person> constructor = clazz.getConstructor(new Class[]{String.class, Integer.class});
    // 获取所有构造方法，包括私有的
    Constructor<?>[] declaredConstructors = clazz.getDeclaredConstructors();
    
    // 记得上边提到的写法吗，我们还能这么写
	Class<? extends Class> clazz = new Person().getClass();
    Constructor<? extends Class>[] constructors = clazz.getConstructors();
    Constructor<? extends Class> constructor = clazz.getConstructor(new Class[]{String.class, Integer.class});
    Constructor<? extends Class>[] declaredConstructors = clazz.getDeclaredConstructors();
}
```

## 获取字段

getFields()：获得某个类的所有的公共（public）的字段，包括父类中的字段。 getDeclaredFields()：获得某个类的所有声明的字段，即包括public、private和proteced，但是不包括父类的声明字段。

```java
public static void main(String[] args) throws Exception {
    Person person = new Person("erosion2020", 14);
    // 获取 Person 类的 Class 对象
    Class<?> clazz = Person.class;
    // 获取所有有访问权限的字段
    Field[] pubFields = clazz.getFields();
    // 获取所有字段，包括私有的
    Field[] fields = clazz.getDeclaredFields();
    // 因为Person中name是private的，如果这里没有访问权限的话是获取不到name这个字段的
    Field name = clazz.getField("name");
    // 这样就可以获取到name字段了（即便没有访问权限也可以通过getDeclaredField直接将字段拿到
    name = clazz.getDeclaredField("name");
    
    // 当name字段没有访问权限时，如果想要修改字段值，则需要设置
    name.setAccessible(true);
    // 然后就能越权给name设置值了
    name.set(person, "AcidEtch")
}

```

## 获取方法

`Class`类提供了以下几个方法来获取`Method`：

- `Method getMethod(name, Class...)`：获取某个`public`的`Method`（包括父类）
- `Method getDeclaredMethod(name, Class...)`：获取当前类的某个`Method`（不包括父类）
- `Method[] getMethods()`：获取所有`public`的`Method`（包括父类）
- `Method[] getDeclaredMethods()`：获取当前类的所有`Method`（不包括父类）

```java
public static void main(String[] args) throws Exception {
    Class<?> clazz = Person.class;
    // 获取所有包含了访问权限的方法
    Method[] pubMethods = clazz.getMethods();
    
    // 获取所有方法，然后输出（即便这个方法是被禁止访问的
	Method[] methods = clazz.getDeclaredMethods();
    
    // 来看个例子，动态调用String.substring(int)方法
    String name = "AcidEtch";
	Method substring = String.class.getMethod("substring", int.class);
	System.out.println(substring.invoke(name,3));
}

```

如果调用的方法是静态方法。那么`invoke`方法传入的第一个参数永远为null

```java
public static void main(String[] args) throws Exception {
	// 获取Integer.parseInt(String)方法，参数为String:
    Method m = Integer.class.getMethod("parseInt", String.class);
    // 调用该静态方法并获取结果:
    Integer n = (Integer) m.invoke(null, "114514");
    System.out.println(n);
}
```

## 创建实例并调用方法 

```java
public static void main(String[] args) throws Exception {
    Class<?> clazz = Person.class;
    // 获取指定参数的构造方法
    Constructor<?> constructor = clazz.getConstructor(String.class, int.class);
    // 通过反射来创建对象
    Object personInstance = constructor.newInstance("John", 30);
    Method introduceMethod = clazz.getMethod("introduce");
    // 通过反射调用打印方法
    introduceMethod.invoke(personInstance);
}

```

## 反射执行exec命令

```java
Class.forName("java.lang.Runtime").getMethod("exec", String.class).invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime")),"cmd /c start");
```

## 修改被final修饰的字段

```java
class Example {
    private final String message = "Initial Value";

    public String getMessage() {
        return message;
    }
}

public class ModifyFinalField {
    public static void main(String[] args) throws Exception {
        Example example = new Example();
        // 输出原始值
        System.out.println("Before modification: " + example.getMessage());
        // 获取 Example 类中 message 字段的 Field 对象
        Field messageField = Example.class.getDeclaredField("message");
        // 设置为可访问
        messageField.setAccessible(true);
        // 修改 final 字段的值
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        // 清除 final 修饰符的影响
        modifiersField.setInt(messageField, messageField.getModifiers() & ~java.lang.reflect.Modifier.FINAL);
        // 修改字段值
        messageField.set(example, "Modified Value");
        // 输出修改后的值
        System.out.println("After modification: " + example.getMessage());
    }
}
```
