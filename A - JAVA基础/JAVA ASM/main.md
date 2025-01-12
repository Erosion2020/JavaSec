ASM这块感觉学起来确实有点理论，内容也是比较抽象的，学完之后都是模模糊糊的，后边如果用到了再回头来复习吧，这里就写个博客记录一下。

参考：https://xz.aliyun.com/t/13334?time__1311=GqmxuiDQiQomqGXeCxUxOxcmkDkSKW4D 大佬介绍的很详细，我这里后半篇直接就拿来用了。

## 什么是ASM？

ASM是一个 **Java字节码操作框架**，全称为 **"Another Symbolic Machine"**。它提供了一个轻量级的工具，用于直接生成、分析、修改Java的字节码。相较于更高级别的Java代码操作工具（如Javassist、BCEL等），ASM具有以下特点：

1. **高效轻量**：以事件驱动的方式操作字节码，效率高且内存占用低。
2. **底层灵活**：直接操作字节码指令，能实现更复杂的功能。
3. **功能强大**：支持动态代理、类生成、性能监控、AOP框架开发等。

ASM被广泛应用于各种Java框架和工具中，比如Spring、Hibernate和Groovy等。它是理解和操作Java字节码的强大工具。

## ASM的核心概念

要理解ASM，首先需要了解一些Java字节码的基本概念。Java的`.class`文件包含了JVM运行所需的字节码，而ASM可以帮助我们直接操作这些字节码。

ASM框架的核心设计基于 **访问者模式**，主要包括以下几个关键类：

1. **`ClassReader`**
   用于读取和解析`.class`文件内容。
2. **`ClassWriter`**
   用于生成或修改`.class`文件内容。
3. **`ClassVisitor`**
   提供一种访问字节码元素（如类、方法、字段等）的回调接口。
4. **`MethodVisitor`**
   用于访问方法字节码的指令序列。
5. **`Opcodes`**
   定义了JVM指令集和相关常量。

ASM以**事件驱动**的方式操作字节码。当解析或生成字节码时，ASM将依次触发一系列回调方法，例如类加载、方法进入、方法字节码访问等，开发者可以在这些回调中实现自己的逻辑。

## 访问者模式

访问者模式（Visitor Pattern）是一种 **行为型设计模式**，它的主要目的是在不修改对象结构的前提下，定义新的操作。这种模式适用于对象结构比较稳定，但需要对其元素定义多种操作的场景。

访问者模式将数据结构和作用于数据结构的操作解耦，使得新增操作更加灵活。

### 核心思想

**元素（Element）**
数据结构中的每个对象（元素）都接受访问者的访问，通常提供一个 `accept` 方法供访问者调用。

**访问者（Visitor）**
定义一系列对数据结构中的元素执行的操作，每种操作是访问者的一个方法。

**双分派机制**
访问者模式依赖于双分派，即：

- 元素通过调用访问者的方法，确定具体操作。
- 访问者根据具体的元素类型，执行特定逻辑。

### **访问者模式的类图**

访问者模式通常包含以下角色：

1. **Visitor（访问者接口）**
   声明针对每种具体元素的访问方法，例如 `visitElementA()` 和 `visitElementB()`。
2. **ConcreteVisitor（具体访问者）**
   实现访问者接口，定义访问每种元素的具体操作。
3. **Element（元素接口）**
   声明 `accept` 方法，接受访问者。
4. **ConcreteElement（具体元素）**
   实现元素接口，调用访问者的 `visit` 方法。
5. **ObjectStructure（对象结构）**
   维护一个元素集合，提供访问者访问这些元素的入口。

### 示例

假设有一个文件系统的结构，包含文件和文件夹，我们希望对这些元素执行多种操作，例如：计算大小、统计数量等。

```java
// 访问者接口
interface Visitor {
    void visit(File file);
    void visit(Folder folder);
}

// 元素接口
interface Element {
    void accept(Visitor visitor);
}

// 文件类
class File implements Element {
    private String name;
    private int size;

    public File(String name, int size) {
        this.name = name;
        this.size = size;
    }

    public String getName() {
        return name;
    }

    public int getSize() {
        return size;
    }

    @Override
    public void accept(Visitor visitor) {
        visitor.visit(this); // 双分派：把自身传递给访问者
    }
}

// 文件夹类
class Folder implements Element {
    private String name;
    private List<Element> elements = new ArrayList<>();

    public Folder(String name) {
        this.name = name;
    }

    public void addElement(Element element) {
        elements.add(element);
    }

    public List<Element> getElements() {
        return elements;
    }

    public String getName() {
        return name;
    }

    @Override
    public void accept(Visitor visitor) {
        visitor.visit(this); // 双分派：把自身传递给访问者
        for (Element element : elements) {
            element.accept(visitor); // 递归访问子元素
        }
    }
}

// 具体访问者：统计文件大小
class SizeCalculator implements Visitor {
    private int totalSize = 0;

    @Override
    public void visit(File file) {
        totalSize += file.getSize();
    }

    @Override
    public void visit(Folder folder) {
        // 文件夹本身不占大小，只访问子元素
    }

    public int getTotalSize() {
        return totalSize;
    }
}

// 具体访问者：统计文件和文件夹数量
class CountCalculator implements Visitor {
    private int fileCount = 0;
    private int folderCount = 0;

    @Override
    public void visit(File file) {
        fileCount++;
    }

    @Override
    public void visit(Folder folder) {
        folderCount++;
    }

    public int getFileCount() {
        return fileCount;
    }

    public int getFolderCount() {
        return folderCount;
    }
}

// 测试代码
public class VisitorPatternDemo {
    public static void main(String[] args) {
        // 创建文件和文件夹
        File file1 = new File("File1.txt", 100);
        File file2 = new File("File2.txt", 200);
        Folder folder = new Folder("MyFolder");
        folder.addElement(file1);
        folder.addElement(file2);

        // 使用访问者1：计算总大小
        SizeCalculator sizeCalculator = new SizeCalculator();
        folder.accept(sizeCalculator);
        System.out.println("Total size: " + sizeCalculator.getTotalSize());

        // 使用访问者2：统计数量
        CountCalculator countCalculator = new CountCalculator();
        folder.accept(countCalculator);
        System.out.println("Files: " + countCalculator.getFileCount());
        System.out.println("Folders: " + countCalculator.getFolderCount());
    }
}
```

运行结果

```java
Total size: 300
Files: 2
Folders: 1
```

### **访问者模式的优点**

1. **增加功能更方便**：可以在不修改元素类的前提下，为其新增操作（只需增加新的访问者）。
2. **解耦结构与操作**：数据结构（如文件、文件夹）与操作（如计算大小、统计数量）分离，便于维护和扩展。

### **访问者模式的缺点**

1. **元素变动难**：如果需要修改数据结构（例如新增一种元素类型），则需要修改所有访问者。
2. **增加复杂性**：访问者模式适用于结构稳定的场景，不适合频繁变动的结构。

### **访问者模式的应用场景**

1. 编译器
   - 分析语法树（AST）中的节点。
2. 数据结构操作
   - 针对复杂的对象结构（如文件系统）定义多种操作。
3. 跨对象操作
   - 在不破坏对象封装的前提下，实现跨类或跨结构的操作。

## 使用ASM

Maven依赖

```
<dependency>
    <groupId>org.ow2.asm</groupId>
    <artifactId>asm</artifactId>
    <version>9.3</version>
</dependency>
```

### 通常处理流程

目标类 class bytes`->`ClassReader 解析`->`ClassVisitor 增强修改字节码`->`ClassWriter 生成增强后的 class bytes`->`通过 Instrumentation 解析加载为新的 Class

## 常用类与方法

### ClassVisitor

用于生成和转换已编译类的 ASM API 是基于 ClassVisitor 抽象类的，将它收到的所有方法调用都委托给另一个 ClassVisitor 类，会调用该类的visitXXX方法，**这个类可以看作一个事件筛选器**

**方法访问顺序**

```
visit visitSource? visitOuterClass? ( visitAnnotation | visitAttribute )*
( visitInnerClass | visitField | visitMethod )*
visitEnd
```

？表示最多一个，*表示任意个

**相关方法**

```java
public abstract class ClassVisitor {
    // 构造方法
    public ClassVisitor(int api);
    public ClassVisitor(int api, ClassVisitor cv);
    // 访问类的基本信息。version参数表示类的版本号，access参数表示类的访问标志，name参数表示类的内部名称，signature参数表示类的泛型签名（如果适用），superName参数表示父类的内部名称，interfaces参数表示类实现的接口的内部名称数组
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces);
    // 访问源文件和调试信息。source参数表示源文件的名称，debug参数表示调试信息
    public void visitSource(String source, String debug);
    // 访问外部类信息。owner参数表示外部类的内部名称，name参数表示外部类的名称，desc参数表示外部类的描述符
    public void visitOuterClass(String owner, String name, String desc);
    // 访问类的注解，返回一个AnnotationVisitor实例，用于访问注解的内容。desc参数表示注解的描述符，visible参数表示注解是否在运行时可见
    AnnotationVisitor visitAnnotation(String desc, boolean visible);
    // 访问类的属性（Attribute），例如SourceFile属性。attr参数表示要访问的属性
    public void visitAttribute(Attribute attr);
    // 访问内部类信息。name参数表示内部类的内部名称，outerName参数表示内部类的外部类的内部名称，innerName参数表示内部类的名称，access参数表示内部类的访问标志
    public void visitInnerClass(String name, String outerName, String innerName, int access);
    // 访问类的字段。access参数表示字段的访问标志，name参数表示字段的名称，desc参数表示字段的描述符，signature参数表示字段的泛型签名（如果适用），value参数表示字段的初始值
    public FieldVisitor visitField(int access, String name, String desc, String signature, Object value);
    // 访问类的方法。access参数表示方法的访问标志，name参数表示方法的名称，desc参数表示方法的描述符，signature参数表示方法的泛型签名（如果适用），exceptions参数表示方法声明的异常类型的内部名称数组
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions);
    // 访问类的结束，表示不再访问该类的任何内容
    void visitEnd();
}
```

### ClassReader

该类解析 ClassFile 内容，并针对遇到的每个字段、方法和字节码指令调用给定 ClassVisitor 的相应访问方法。**这个类可以看作一个事件生产者**

**构造方法**

```java
public ClassReader(byte[] classFile)
// classFile - the JVMS ClassFile structure to be read.
```

**方法**

```java
public void accept(ClassVisitor classVisitor, int parsingOptions)
// classVisitor - the visitor that must visit this class.
// parsingOptions - the options to use to parse this class. One or more of SKIP_CODE, SKIP_DEBUG,SKIP_FRAMES or EXPAND_FRAMES.
```

### ClassWriter

ClassWriter 类是 ClassVisitor 抽象类的一个子类，它直接以二进制形式生成编译后的类。它会生成一个字节数组形式的输出，其中包含了已编译类，可以用 toByteArray 方法来提取。**这个类可以看作一个事件消费者**

**构造方法**

```java
public ClassWriter(int flags)
// Constructs a new ClassWriter object.
public ClassWriter(ClassReader classReader, int flags)
// Constructs a new ClassWriter object and enables optimizations for "mostly add" bytecode transformations.
```

**方法**

```java
public byte[] toByteArray()
// Returns the content of the class file that was built by this ClassWriter.
// Returns:
// the binary content of the JVMS ClassFile structure that was built by this ClassWriter.
```

### MethodVisitor

访问Java方法的访问者类，用于生成和转换已编译方法的 ASM API 是基于 MethodVisitor 抽象类的，它由 ClassVisitor 的 visitMethod 方法返回。

**方法访问顺序**

```
visitAnnotationDefault?
( visitAnnotation | visitParameterAnnotation | visitAttribute )*
( visitCode
( visitTryCatchBlock | visitLabel | visitFrame | visitXxxInsn | visitLocalVariable | visitLineNumber )*
visitMaxs )?
visitEnd
```

对非抽象方法，如果存在注解和属性，必须先访问；其次是按顺序访问字节代码，这些访问在visitCode与visitMaxs之间

**相关方法**

```java
abstract class MethodVisitor { // public accessors ommited
   // 构造方法
   MethodVisitor(int api);
   MethodVisitor(int api, MethodVisitor mv);

   // 访问方法的注解默认值
   AnnotationVisitor visitAnnotationDefault();
   // 访问方法的注解
   AnnotationVisitor visitAnnotation(String desc, boolean visible);
   // 访问方法参数的注解
   AnnotationVisitor visitParameterAnnotation(int parameter,
   String desc, boolean visible);
   // 访问方法的属性
   void visitAttribute(Attribute attr);
   // 访问方法的字节码指令部分
   void visitCode();

   // 访问方法的帧（Frame）。type参数表示帧的类型，nLocal参数表示局部变量的数量，local参数表示局部变量数组，nStack参数表示操作数栈的数量，stack参数表示操作数栈数组
   void visitFrame(int type, int nLocal, Object[] local, int nStack,
   Object[] stack);
   // 访问方法的一条指令，指令没有操作数
   void visitInsn(int opcode);
   // 访问方法的一条指令，指令操作数为单个整数
   void visitIntInsn(int opcode, int operand);
   // 访问方法的一条指令，指令操作数为局部变量索引
   void visitVarInsn(int opcode, int var);
   // 访问方法的一条指令，指令操作数为类型描述符
   void visitTypeInsn(int opcode, String desc);
   // 访问方法的一条指令，指令操作数为字段的信息。opc参数表示指令的操作码，owner参数表示字段所属的类名，name参数表示字段的名称，desc参数表示字段的描述符
   void visitFieldInsn(int opc, String owner, String name, String desc);
   // 访问方法的一条指令，指令操作数为方法的信息。opc参数表示指令的操作码，owner参数表示方法所属的类名，name参数表示方法的名称，desc参数表示方法的描述符
   void visitMethodInsn(int opc, String owner, String name, String desc);
   // 访问方法的一条动态方法调用指令。name参数表示方法的名称，desc参数表示方法的描述符，bsm参数表示引导方法（bootstrap method）的句柄，bsmArgs参数表示引导方法的参数。
   void visitInvokeDynamicInsn(String name, String desc, Handle bsm, Object... bsmArgs);
   // 访问方法的一条跳转指令
   void visitJumpInsn(int opcode, Label label);
   // 访问方法的标签（Label），用于标记代码的位置
   void visitLabel(Label label);
   // 访问方法的一条指令，将常量加载到操作数栈上
   void visitLdcInsn(Object cst);
   // 访问方法的一条指令，对局部变量进行增量操作
   void visitIincInsn(int var, int increment);
   // 访问方法的一条表格跳转指令。min参数表示最小的键值，max参数表示最大的键值，dflt参数表示默认跳转目标的标签，labels参数表示每个键值对应的跳转目标的标签数组
   void visitTableSwitchInsn(int min, int max, Label dflt, Label[] labels);
   // 访问方法的一条查找跳转指令。dflt参数表示默认跳转目标的标签，keys参数表示键值数组，labels参数表示每个键值对应的跳转目标的标签数组
   void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels);
   // 访问方法的一条多维数组创建指令。desc参数表示数组的元素类型的描述符，dims参数表示数组的维度
   void visitMultiANewArrayInsn(String desc, int dims);
   // 访问方法的一个try-catch块。start参数表示try块的起始标签，end参数表示try块的结束标签，handler参数表示catch块的处理程序标签，type参数表示捕获的异常类型的描述符
   void visitTryCatchBlock(Label start, Label end, Label handler, String type);
   // 访问方法的局部变量。name参数表示局部变量的名称，desc参数表示局部变量的描述符，signature参数表示局部变量的泛型签名（如果适用），start参数表示变量的作用域的起始标签，end参数表示变量的作用域的结束标签，index参数表示局部变量的索引
   void visitLocalVariable(String name, String desc, String signature, Label start, Label end, int index);
   // 访问方法的行号信息。line参数表示行号，start参数表示行号对应的代码位置的标签
   void visitLineNumber(int line, Label start);
   // 访问方法的最大栈大小和最大局部变量数量。maxStack参数表示最大栈大小，maxLocals参数表示最大局部变量数量
   void visitMaxs(int maxStack, int maxLocals);
   // 访问方法的结束，表示不再访问该方法的任何内容
   void visitEnd();
}
```

**修改方法的步骤：原始方法和修改后的方法编译后进行对比，在通过visit操作进行修改**

## 解析字节码

### ClassReader加载字节码

该类解析 ClassFile 内容，并针对遇到的每个字段、方法和字节码指令调用给定 ClassVisitor 的相应访问方法。

**构造方法**

```java
public ClassReader(byte[] classFile)
// classFile - the JVMS ClassFile structure to be read.
```

**方法**

```java
public void accept(ClassVisitor classVisitor, int parsingOptions)
// classVisitor - the visitor that must visit this class.
// parsingOptions - the options to use to parse this class. One or more of SKIP_CODE, SKIP_DEBUG,SKIP_FRAMES or EXPAND_FRAMES.
```

**实例**

```java
// 从文件系统中加载字节码
byte[] bytecode = Files.readAllBytes(Paths.get("path/to/MyClass.class"));
// 或者
 FileInputStream bytecode = new FileInputStream("path/to/MyClass.class");

// 从类加载器中加载字节码
InputStream is = getClass().getClassLoader().getResourceAsStream("com/example/MyClass.class");
byte[] bytecode = is.readAllBytes();

// 创建ClassReader实例
ClassReader classReader = new ClassReader(bytecode);
```

### ClassVisitor解析字节码

访问者，可根据具体要定义继承该类的访问类，并重写其方法

**构造方法**

```java
protected ClassVisitor(int api)
protected ClassVisitor(int api, ClassVisitor classVisitor)
// api:该访问者执行的 ASM API 版本
// classVisitor:类访问者，该访问者必须将方法调用委托给该类访问者
```

**方法**

```java
public void visit(int version, int access, String name, String signature, String superName, String[] interfaces)
// Visits the header of the class.
```

- version：表示类文件的 JDK 版本
- access：表示类的访问权限和属性
- name：类的内部名称，用斜线代替点分隔包名和类名
- signature：类的泛型签名，如果类没有泛型信息，此参数为 null
- superName：父类的内部名称
- interfaces：类实现的接口的内部名称数组。如果类没有实现任何接口，此参数为空数组

**实例**

实验类：bytecodeTest

```java
package bytecode;
public class bytecodeTest extends Person implements helloInterface{
    private String sex;
    public bytecodeTest(String name, int age, String sex) {
        super(name, age);
        this.sex = sex;
    }
    public void sayHello() {
        System.out.println("Hello" + super.name);
    }
}
```

访问者类：MyClassVisitor

```java
package javaasm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public class MyClassVisitor extends ClassVisitor {
    // 调用父类构造方法，使用ASM Opcodes版本
    public MyClassVisitor() {
        super(Opcodes.ASM5);
    }

    // 重写visit方法，输出类名
    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        // print class name
        System.out.println("The class name:" + name);
        super.visit(version, access, name, signature, superName, interfaces);
    }

    // 重写visitMethod方法，输出方法名
    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        // print method name
        System.out.println("The method name:" + name);
        return super.visitMethod(access, name, descriptor, signature, exceptions);
    }
}
```

结果

```java
The class name:bytecode/bytecodeTest
The method name:<init>
The method name:sayHello

Process finished with exit code 0
```

## 修改字节码

### 添加与删除Field

**实例**

删除sex属性，增加address属性

实验类：bytecodeTest

访问者类：UpdateFieldClassVisitor

```java
package javaasm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Opcodes;

public class UpdateFieldClassVisitor extends ClassVisitor {
    // 删除字段的name
    private String deleteFieldName;
    // 添加字段的访问修饰符
    private int addFieldAcc;
    // 添加字段的name
    private String addFieldName;
    // 添加字段的描述符(类型)
    private String addFieldDesc;

    private Boolean flag = false;

    protected UpdateFieldClassVisitor(ClassVisitor cv, String deleteFieldName, int addFieldAcc, String addFieldName, String addFieldDesc) {
        super(Opcodes.ASM5, cv);
        this.deleteFieldName = deleteFieldName;
        this.addFieldAcc = addFieldAcc;
        this.addFieldName = addFieldName;
        this.addFieldDesc = addFieldDesc;
    }

    @Override
    public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
        // 删除名为deleteFieldName的字段
        if (name.equals(deleteFieldName)) {
            return null;
        }
        if (name.equals(addFieldName)) flag = true;
        return super.visitField(access, name, descriptor, signature, value);
    }

    @Override
    public void visitEnd() {
        // 添加名为addFieldName的字段
        if (!flag) {
            FieldVisitor fieldVisitor = super.visitField(addFieldAcc, addFieldName, addFieldDesc, null, null);
            if (fieldVisitor != null) {
                fieldVisitor.visitEnd();
            }
        }
        super.visitEnd();
    }
}
```

测试类：Main

```java
package javaasm;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Main {
    public static void main(String[] args) throws Exception{
        // -------------------添加与删除Field-------------------
        FileInputStream stream = new FileInputStream("target/classes/bytecode/bytecodeTest.class");
        // 加载字节码
        ClassReader reader = new ClassReader(stream);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
        // 实例化修改Field Visitor
        UpdateFieldClassVisitor updateFieldClassVisitor = new UpdateFieldClassVisitor(writer, "sex", Opcodes.ACC_PRIVATE, "address", "Ljava/lang/String;");
        // 调用accept
        reader.accept(updateFieldClassVisitor, ClassReader.EXPAND_FRAMES);
        FileOutputStream fileOutputStream = new FileOutputStream("temp.class");
        byte[] updateByte = writer.toByteArray();
        fileOutputStream.write(updateByte);
        fileOutputStream.close();
        // 测试
        ClassReader classReader = new ClassReader(updateByte);
        MyClassVisitor myClassVisitor = new MyClassVisitor();
        classReader.accept(myClassVisitor, 0);
    }
}
```

结果

```java
The class name:bytecode/bytecodeTest
The field name:address
The method name:<init>
The method name:sayHello

Process finished with exit code 0
```

### 添加与删除Method

**实例**

删除sayHello方法，增加newMethod方法

实验类：bytecodeTest

访问者类：UpdateMethodClassVisitor

```java
package javaasm;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public class UpdateMethodClassVisitor extends ClassVisitor {
    private String deleteMethodName;
    private String deleteMethodDesc;
    private int addMethodAcc;
    private String addMethodName;
    private String addMethodDesc;
    private boolean flag = false;

    protected UpdateMethodClassVisitor(ClassVisitor cv, String deleteMethodName, String deleteMethodDesc, int addMethodAcc,
                                       String addMethodName, String addMethodDesc) {
        super(Opcodes.ASM5, cv);
        this.deleteMethodName = deleteMethodName;
        this.deleteMethodDesc = deleteMethodDesc;
        this.addMethodAcc = addMethodAcc;
        this.addMethodName = addMethodName;
        this.addMethodDesc = addMethodDesc;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        // 删除名为deleteMethodName且描述为deleteMethodDesc的方法
        // 因为有的方法可能name一致，但是参数不同
        if (name.equals(deleteMethodName) && descriptor.equals(deleteMethodDesc)) {
            return null;
        }
        if (name.equals(addMethodName) && descriptor.equals(addMethodDesc)) flag = true;
        return super.visitMethod(access, name, descriptor, signature, exceptions);
    }

    @Override
    public void visitEnd() {
        // 添加名为addMethodName且描述为addMethodDesc的方法
        if (!flag) {
            MethodVisitor methodVisitor = super.visitMethod(addMethodAcc, addMethodName, addMethodDesc, null, null);
            if (methodVisitor != null) {
                // 访问方法的字节码
                methodVisitor.visitCode();
                // 添加return指令
                methodVisitor.visitInsn(Opcodes.RETURN);
                // 设置方法的最大操作数栈深度和最大局部变量表大小，空方法设置00即可
                methodVisitor.visitMaxs(0, 0);
                // 结束访问
                methodVisitor.visitEnd();
            }
        }
        super.visitEnd();
    }
}
```

测试类Main

```java
package javaasm;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Main {
    public static void main(String[] args) throws Exception{
        // -------------------添加与删除Method-------------------
        FileInputStream stream = new FileInputStream("target/classes/bytecode/bytecodeTest.class");
        // 加载字节码
        ClassReader reader = new ClassReader(stream);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
        // 实例化修改Method Visitor
        UpdateMethodClassVisitor updateMethodClassVisitor = new UpdateMethodClassVisitor(writer, "sayHello", "()V", Opcodes.ACC_PUBLIC, "newMethod", "()V");
        reader.accept(updateMethodClassVisitor, ClassReader.EXPAND_FRAMES);
        // 写入新class中
        FileOutputStream fileOutputStream = new FileOutputStream("temp.class");
        byte[] updateByte = writer.toByteArray();
        fileOutputStream.write(updateByte);
        fileOutputStream.close();
        // 测试
        ClassReader classReader = new ClassReader(updateByte);
        MyClassVisitor myClassVisitor = new MyClassVisitor();
        classReader.accept(myClassVisitor, 0);
    }
}
```

结果

```java
The class name:bytecode/bytecodeTest
The field name:sex
The method name:<init>
The method name:newMethod

Process finished with exit code 0
```

### 修改方法指令

**实例**

在方法开头加入输出语句

实验类：bytecodeTest

方法适配器：ModMethodAdapter

```java
package javaasm;


import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public class ModMethodAdapter extends MethodVisitor {

    public ModMethodAdapter(MethodVisitor methodVisitor) {
        super(Opcodes.ASM5, methodVisitor);
    }

    @Override
    public void visitCode() {
        // 在方法前面添加输出
        // 从java/lang/System类中获取名为out的静态字段，该字段的类型为java/io/PrintStream
        // GETSTATIC指令将该字段的值压入操作数栈上
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        // LDC指令用于将常量加载到栈上
        mv.visitLdcInsn("Hello, World!");
        // 调用java/io/PrintStream类的println方法，它接受一个java/lang/String类型的参数，并且没有返回值
        // INVOKEVIRTUAL指令用于调用实例方法
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        super.visitCode();
    }
}
```

访问者类：ModMethodVisitor

```java
package javaasm;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
public class ModMethodVisitor extends ClassVisitor {
    protected ModMethodVisitor(ClassVisitor classVisitor) {
        super(Opcodes.ASM5, classVisitor);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor methodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions);
        return new ModMethodAdapter(methodVisitor);
    }
}
```

测试类：Main

```java
package javaasm;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Main {
    public static void main(String[] args) throws Exception{
        // -------------------修改Method：向方法开头加入输出-------------------
        FileInputStream stream = new FileInputStream("target/classes/bytecode/bytecodeTest.class");
        // 加载字节码
        ClassReader reader = new ClassReader(stream);
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
        // 实例化修改Method Visitor
        ModMethodVisitor modMethodVisitor = new ModMethodVisitor(writer);
        reader.accept(modMethodVisitor, ClassReader.EXPAND_FRAMES);
        // 写入新class中
        FileOutputStream fileOutputStream = new FileOutputStream("temp.class");
        byte[] updateByte = writer.toByteArray();
        fileOutputStream.write(updateByte);
        fileOutputStream.close();
        // 测试
        ClassReader classReader = new ClassReader(updateByte);
        MyClassVisitor myClassVisitor = new MyClassVisitor();
        classReader.accept(myClassVisitor, 0);
    }
}
```

## 用途

安全审计：ASM可以帮助进行Java代码的安全审计。通过解析和分析字节码，可以识别潜在的安全漏洞、代码注入、恶意操作等问题。ASM提供了丰富的API，能够检查和分析类、方法和指令，以发现可能的安全风险。

安全增强：ASM可以用于对Java应用程序进行安全增强。可以使用ASM修改字节码，以添加安全检查、权限验证、异常处理等安全相关的功能。这有助于在运行时保护应用程序免受潜在的攻击和漏洞利用。

加密和混淆：ASM可以与其他安全工具结合使用，以实现代码加密和混淆。通过修改字节码，可以对敏感的代码片段进行加密，以防止反编译和代码泄露。此外，ASM还可以帮助将代码进行混淆，使其更难以理解和分析。

本文为后续研究Java自动化漏洞挖掘IAST与RASP打基础

## 参考链接

- [ASM 4.0 A Java bytecode engineering library (ow2.io)](https://asm.ow2.io/asm4-guide.pdf)
- [org.objectweb.asm (ASM 9.6) (ow2.io)](https://asm.ow2.io/javadoc/org/objectweb/asm/package-summary.html)