# Log4jHotPatch

Kudos to Volker Simonis for the original patch, he continues to amaze and
delight in the Java industry :-) - Original patch at https://github.com/corretto/hotpatch-for-apache-log4j2

This is a tool which injects a Java agent into a running JVM process. The agent will attempt to patch the `lookup()` method of all loaded `org.apache.logging.log4j.core.lookup.JndiLookup` instances to unconditionally return the string "Patched JndiLookup::lookup()". It is designed to address the [CVE-2021-44228](https://www.randori.com/blog/cve-2021-44228/) remote code execution vulnerability in Log4j without restarting the Java process.

The dynamic and static agents are known to run on JDK 8 & 11 on Linux whereas on JDK 17 only the static agent is working (see below).

## Building

JDK 8
```
javac -XDignore.symbol.file=true -cp <java-home>/lib/tools.jar Log4jHotPatch.java
```

JDK 11+
```
javac --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED --add-exports=jdk.internal.jvmstat/sun.jvmstat.monitor=ALL-UNNAMED Log4jHotPatch.java
```

### Building a static agent

After compiling as described above, build the agent jar file as follows:
```
jar -cfm Log4jHotPatch.jar Manifest.mf *.class
```

## Running

JDK 8
```
java -cp .:<java-home>/lib/tools.jar Log4jHotPatch <java-pid>
```

JDK 11
```
java Log4jHotPatch <java-pid>
```

### Running the static agent

Simply add the agent to your java command line as follows:
```
java -classpath <class-path> -javaagent:Log4jHotPatch.jar <main-class> <arguments>
```

To make this tool as simple and self-contained as possible, it uses OpenJDK's internal copy of the [ObjectWeb ASM](https://asm.ow2.io/) library in the target JVM. In JDK 17 the strong encapsulation of this library can only be bypassed with a command line option. This is why the reason why applications running on JDK 17 can currently only be patched with the static version of the agent:
```
java --add-exports=java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED -classpath <class-path> -javaagent:Log4jHotPatch.jar <main-class> <arguments>
```

## Known issues

If you get an error like:
```
Exception in thread "main" com.sun.tools.attach.AttachNotSupportedException: The VM does not support the attach mechanism
	at jdk.attach/sun.tools.attach.HotSpotAttachProvider.testAttachable(HotSpotAttachProvider.java:153)
	at jdk.attach/sun.tools.attach.AttachProviderImpl.attachVirtualMachine(AttachProviderImpl.java:56)
	at jdk.attach/com.sun.tools.attach.VirtualMachine.attach(VirtualMachine.java:207)
	at Log4jHotPatch.loadInstrumentationAgent(Log4jHotPatch.java:115)
	at Log4jHotPatch.main(Log4jHotPatch.java:139)
```
this means that your JVM is refusing any kind of help because it is running with `-XX:+DisableAttachMechanism`.

If you get an error like:
```
com.sun.tools.attach.AttachNotSupportedException: Unable to open socket file: target process not responding or HotSpot VM not loaded
	at sun.tools.attach.LinuxVirtualMachine.<init>(LinuxVirtualMachine.java:106)
	at sun.tools.attach.LinuxAttachProvider.attachVirtualMachine(LinuxAttachProvider.java:63)
	at com.sun.tools.attach.VirtualMachine.attach(VirtualMachine.java:208)
	at Log4jHotPatch.loadInstrumentationAgent(Log4jHotPatch.java:182)
	at Log4jHotPatch.main(Log4jHotPatch.java:259)
```
this means you're running as a different user (including root) than the target JVM. JDK 8 can't handle patching as root user (and triggers a thread dump in the target JVM which is harmless). In JDK 11 patching a non-root process from a root process works just fine.

**Important:** If you attempted to patch as the wrong user, you may need to delete `.attach_pid<pid>` files (found in `/tmp` and/or the CWD of the VM process) before trying again. These files need to have the right ownership for attach to succeed.
