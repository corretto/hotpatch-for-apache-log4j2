# Log4jHotPatch

This is a tool which injects a Java agent into a running JVM process. The agent will attempt to patch the `lookup()` method of all loaded `org.apache.logging.log4j.core.lookup.JndiLookup` instances to unconditionally return the string "Patched JndiLookup::lookup()". It is designed to address the [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228/) remote code execution vulnerability in Log4j without restarting the Java process. This tool will also address [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046/).

This has been currently only tested with JDK 8, 11, 15 and 17 on Linux!

## Building
To build on linux, mac and Windows subsystem for linux
```
./gradlew build
```
To build on Windows
```
.\gradlew.bat build
```
Depending on the platform you are building. This will generate `build/libs/Log4jHotPatch.jar`

## Running

JDK 8
```
java -cp <java-home>/lib/tools.jar:Log4jHotPatch.jar Log4jHotPatch <java-pid>
```

JDK 11 and newer
```
java -jar Log4jHotPatch.jar <java-pid>
```

### Running the static agent

Simply add the agent to your java command line as follows:
```
java -classpath <class-path> -javaagent:Log4jHotPatch.jar <main-class> <arguments>
```

### Testing the agent
There are a set of tests that can be run outside gradle.
```
build-tools/bin/run_tests.sh build/libs/Log4jHotPatch.jar <JDK_ROOT>
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

If you get an error like this in the target process:
```
Exception in thread "Attach Listener" java.lang.ExceptionInInitializerError
        at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
        at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
        at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
        at java.lang.reflect.Method.invoke(Method.java:498)
        at sun.instrument.InstrumentationImpl.loadClassAndStartAgent(InstrumentationImpl.java:386)
        at sun.instrument.InstrumentationImpl.loadClassAndCallAgentmain(InstrumentationImpl.java:411)
Caused by: java.security.AccessControlException: access denied ("java.util.PropertyPermission" "log4jFixerAgentVersion" "write")
        at java.security.AccessControlContext.checkPermission(AccessControlContext.java:472)
        at java.security.AccessController.checkPermission(AccessController.java:886)
        at java.lang.SecurityManager.checkPermission(SecurityManager.java:549)
        at java.lang.System.setProperty(System.java:794)
        at Log4jHotPatch.<clinit>(Log4jHotPatch.java:66)
```
it means the target process has a security manager installed. Look for this command line option in the target process:
```
-Djava.security.policy=/local/apollo/.../apollo-security.policy
```
If you encounter this error, make sure you are using the latest version of the tool

**Important:** If you attempted to patch as the wrong user, you may need to delete `.attach_pid<pid>` files (found in `/tmp` and/or the CWD of the VM process) before trying again. These files need to have the right ownership for attach to succeed.
