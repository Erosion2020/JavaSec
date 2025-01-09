`Apache Wicket`直接CV了 FileUpload 中的代码，所以FileUpload中的攻击链在`Apache Wicket`中同样使用，所以Wicket的攻击链就是FileUpload......。

## 环境准备

JDK任意即可，我这里用的是JDK8u66，和FileUpload这条链的一样的，但需要加入以下依赖项：

```xml
<!-- https://mvnrepository.com/artifact/org.slf4j/slf4j-api -->
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>1.6.4</version>
</dependency>
<!-- https://mvnrepository.com/artifact/org.apache.wicket/wicket-util -->
<dependency>
    <groupId>org.apache.wicket</groupId>
    <artifactId>wicket-util</artifactId>
    <version>6.23.0</version>
</dependency>
```

## POC链接

参考我写的`fileupload`攻击链：[fileupload攻击链](../FileUpload/main.md)