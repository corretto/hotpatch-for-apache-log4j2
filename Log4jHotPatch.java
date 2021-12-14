/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.nio.file.Files;
import java.nio.file.FileSystems;
import java.nio.file.Paths;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

import jdk.internal.org.objectweb.asm.ClassReader;
import jdk.internal.org.objectweb.asm.ClassVisitor;
import jdk.internal.org.objectweb.asm.ClassWriter;
import jdk.internal.org.objectweb.asm.MethodVisitor;
import jdk.internal.org.objectweb.asm.Opcodes;

/**
 * See https://github.com/advisories/GHSA-jfh8-c2jp-5v3q/dependabot
 * <p>
 * Kudos to Volker Simonis for the original patch, he continues to amaze and
 * delight in the Java industry :-) - https://github.com/simonis/Log4jPatch
 * <p>
 * WARNING: HERE BE DRAGONS and DANGER WILL ROBINSON!
 * <p>
 * This patch should only ever be run if:
 * <p>
 * 1. You are unable to upgrade your log4j to 2.15.0 and/or restart your JVM
 * 2. You are unable to change the system property as per
 * https://logging.apache.org/log4j/2.x/security.html and/or restart your JVM
 * 3. You are willing to risk freezing your live running JVM (which would mean
 * you would have to restart it anyhow.)
 * <p>
 * This is a class is an all-in-one utility that:
 * <p>
 * 1. Turns itself into a Java Agent
 * 2. Attaches to all viable JVMs (running as the same user)
 * 3. Uses a ClassWalker visitor to find the vulnerable
 * org/apache/logging/log4j/core/lookup/JndiLookup method and patches it
 * using ASM to override the return to return nothing.
 * <p>
 * See the README.md file for javac configuration (--add-exports is required)
 */
public class Log4jHotPatch {

  // version of this agent
  private static final int LOG_4_J_FIXER_AGENT_VERSION = 1;

  // property name for verbose flag
  public static final String LOG4J_FIXER_VERBOSE = "log4jFixerVerbose";

  // property name for interactive flag
  public static final String LOG4J_FIXER_INTERACTIVE = "log4jFixerInteractive";

  // property name for the agent version
  private static final String LOG4J_FIXER_AGENT_VERSION = "log4jFixerAgentVersion";

  private static boolean verbose = Boolean.parseBoolean(System.getProperty(LOG4J_FIXER_VERBOSE, "true"));

  // Interactive mode is off by default
  private static boolean interactive = Boolean.parseBoolean(System.getProperty(LOG4J_FIXER_INTERACTIVE, "false"));

  static {
    // set the version of this agent
    System.setProperty(LOG4J_FIXER_AGENT_VERSION, String.valueOf(LOG_4_J_FIXER_AGENT_VERSION));
  }

  private static void logInfo(String message) {
    if (verbose) {
      System.out.println(message);
    }
  }

  private static void logError(String message) {
    if (verbose) {
      System.err.println(message);
    }
  }

  private static boolean staticAgent = false; // Set to true if loaded as a static agent from 'premain()'

  /**
   * Detect and return the ASM version to use.
   *
   * @return The ASM version
   */
  private static int asmVersion() {
    try {
      Opcodes.class.getDeclaredField("ASM8");
      return 8 << 16 | 0 << 8; // Opcodes.ASM8
    } catch (NoSuchFieldException nsfe) {
      // Deliberately do not log
    }
    try {
      Opcodes.class.getDeclaredField("ASM7");
      return 7 << 16 | 0 << 8; // Opcodes.ASM7
    } catch (NoSuchFieldException nsfe) {
      // Deliberately do not log
    }
    try {
      Opcodes.class.getDeclaredField("ASM6");
      return 6 << 16 | 0 << 8; // Opcodes.ASM6
    } catch (NoSuchFieldException nsfe) {
      // Deliberately do not log
    }
    try {
      Opcodes.class.getDeclaredField("ASM5");
      return 5 << 16 | 0 << 8; // Opcodes.ASM5
    } catch (NoSuchFieldException nsfe) {
      // Deliberately do not log
    }
    logError("Warning: ASM5 doesn't seem to be supported, defaulting to ASM4");
    return Opcodes.ASM4;
  }

  /**
   * The main method for the JavaAgent that we use for performing the transform
   *
   * @param args            Required parameter (but is empty in this case)
   * @param instrumentation The instrumentation class we'll use to transform.
   */
  public static void agentmain(String args, Instrumentation instrumentation) {

    verbose = args == null || "log4jFixerVerbose=true".equals(args);
    int asm = asmVersion();
    logInfo("Loading Java Agent version " + LOG_4_J_FIXER_AGENT_VERSION + " (using ASM" + (asm >> 16) + ").");

    ClassFileTransformer transformer = new ClassFileTransformer() {

      /**
       * When the agent runs this transform function will be fired. It
       * visits all the classes in the target JVM looking for the
       * LOG4J_JNDI_CLASS_TO_PATCH class to transform the lookup() method.
       *
       * @param loader - Classloader used to start searching
       * @param className - The class we are looking for
       * @param classBeingRedefined - Not used
       * @param protectionDomain - Not used
       * @param classfileBuffer - Not used
       * @return The transformed class/method
       */
      @Override
      public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {

        if (className != null && className.endsWith("org/apache/logging/log4j/core/lookup/JndiLookup")) {
            logInfo("Transforming " + className + " (" + loader + ")");
            ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            MethodInstrumentorClassVisitor classVisitor = new MethodInstrumentorClassVisitor(asm, classWriter);
            ClassReader classReader = new ClassReader(classfileBuffer);
            classReader.accept(classVisitor, 0);
            return classWriter.toByteArray();
          } else {
            return null;
          }
        }
      };

    if (!staticAgent) {
      int patchesApplied = 0;

      instrumentation.addTransformer(transformer, true);

      for (Class<?> aClass : instrumentation.getAllLoadedClasses()) {
        String className = aClass.getName();
        if (className.endsWith("org.apache.logging.log4j.core.lookup.JndiLookup")) {
          logInfo("Patching " + aClass + " (" + aClass.getClassLoader() + ")");
          try {
            instrumentation.retransformClasses(aClass);
            ++patchesApplied;
          } catch (UnmodifiableClassException uce) {
            logError(String.valueOf(uce));
          }
        }
      }

      if (patchesApplied == 0) {
        logInfo("Vulnerable classes were not found. This agent will continue to run " +
            "and transform the vulnerable class if it is loaded. Note that if you have shaded " +
            "or otherwise changed the package name for log4j classes, then this tool may not " +
            "find them.");
      }

      instrumentation.removeTransformer(transformer);
    }

    // Re-add the transformer with 'canRetransform' set to false
    // for class instances which might get loaded in the future.
    instrumentation.addTransformer(transformer, false);
  }

  /**
   * The premain method for the JavaAgent that we use for performing the transform
   *
   * @param args            Required parameter (but is empty in this case)
   * @param instrumentation The instrumentation class we'll use to transform.
   */
  public static void premain(String args, Instrumentation instrumentation) {
    staticAgent = true;
    agentmain(args, instrumentation);
  }

  /**
   * The visitor that finds the lookup() method that we want to transform
   */
  static class MethodInstrumentorClassVisitor extends ClassVisitor {
    private int asm;

    public MethodInstrumentorClassVisitor(int asm, ClassVisitor cv) {
      super(asm, cv);
      this.asm = asm;
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
      MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
      if ("lookup".equals(name)) {
        mv = new MethodInstrumentorMethodVisitor(asm, mv);
      }
      return mv;
    }
  }

  /**
   * The Visitor class that applies the patch via ASM
   * It forces an empty return for the vulnerable lookup() method
   */
  static class MethodInstrumentorMethodVisitor extends MethodVisitor implements Opcodes {

    public MethodInstrumentorMethodVisitor(int asm, MethodVisitor mv) {
      super(asm, mv);
    }

    @Override
    public void visitCode() {
      mv.visitCode();
      mv.visitLdcInsn("Patched JndiLookup::lookup()");
      mv.visitInsn(ARETURN);
    }
  }

  // Name of this class, used for filtering myself out of the patching process
  private static String myName = Log4jHotPatch.class.getName();

  /**
   * Patch all the JVMs that we find.
   *
   * @param pids - List of pids for the target JVMs
   * @throws Exception
   */
  private static boolean patchJVMs(String... pids) throws Exception {
    boolean allSucceeded = true;

    Map<String, Boolean> successMatrix = new HashMap<>();

    File jarFile = createAgentJar();

    String we = getUID("self");
    for (String pid : pids) {
      if (pid != null) {
        boolean success = patchJVM(jarFile, we, pid);
        successMatrix.put(pid, success);
        if (!success) {
          allSucceeded = false;
        }
      }
    }

    // TODO improve formatting
    logInfo("Success Matrix: " + successMatrix.toString());
    return allSucceeded;
  }

  /**
   * Patch a JVM by connecting to it via ourselves as a Java Agent.
   * When the agent attaches the payload is delivered (see agentmain method)
   *
   * @param jarFile   The Java Agent (ourselves)
   * @param we        Ourselves to filter out
   * @param pid       The pid of the JVM
   * @return Whether the agent attach worked.
   */
  private static boolean patchJVM(File jarFile, String we, String pid) {
    if (pid != null) {
      try {
        // Check if we're running under the same UID like the target JVM.
        // If not, log warning as it might fail to attach.
        if (we != null && !we.equals(getUID(pid))) {
          logInfo("\nWarning: patching for JVM process " + pid + " might fail because it runs under a different user");
          logInfo("  Our uid == " + we + ", their uid == " + getUID(pid));
        }

        VirtualMachine vm = VirtualMachine.attach(pid);

        // If the target VM is already patched then skip.
        // Notice that the agent class gets loaded by the system class loader, so we
        // can't unload or update it. If we'd re-deploy the agent one more time, we'd
        // just rerun 'agentmain()' from the already loaded agent version.
        Properties props = vm.getSystemProperties();
        if (props == null) {
          logError("Error: could not verify 'log4jFixerAgentVersion' in JVM process " + pid);
          return false;
        }
        String version = props.getProperty(LOG4J_FIXER_AGENT_VERSION);
        if(version != null) {
          logInfo("Skipping patch for JVM process " + pid + ", patch version " + version + " already applied");
          return true;
        }

        // unpatched target VM, apply patch
        vm.loadAgent(jarFile.getAbsolutePath(), "log4jFixerVerbose=" + verbose);
      } catch (Exception e) {
        if (verbose) {
          e.printStackTrace(System.err);
          logError("Error: couldn't load the agent into JVM process " + pid);
          logError("  Are you running as a different user (including root) than the process " + pid + "?");
        }
        return false;
      }
      logInfo("Successfully loaded the agent into JVM process " + pid);
      logInfo("  Look at stdout of JVM process " + pid + " for more information");
    }
    return true;
  }

  /**
   * This method creates the JAR file which is an Agent and effectively puts
   * itself inside the agent.
   *
   * @return The JAR file (which is a Java Agent) with this class's bytecode
   * embedded in it, ready to be executed
   * @throws Exception
   */
  private static File createAgentJar() throws Exception {
    String[] innerClasses = {"", /* this is for Log4jHotPatch itself */
                             "$1",
                             "$MethodInstrumentorClassVisitor",
                             "$MethodInstrumentorMethodVisitor"};

    Manifest manifest = createManifest();

    // Create agent jar file on the fly
    File jarFile = File.createTempFile("agent", ".jar");
    jarFile.deleteOnExit();

    try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(Paths.get(jarFile.getAbsolutePath())), manifest)) {
      byte[] buf;
      JarEntry jarEntry;
      for (String klass : innerClasses) {
        String className = myName.replace('.', '/') + klass;
        buf = getBytecodes(className);
        jarEntry = new JarEntry(className + ".class");
        jar.putNextEntry(jarEntry);
        jar.write(buf);
      }
    }
    return jarFile;
  }

  /**
   * Create the manifest entry for the JAR file (which is a Java Agent).
   * JAR files need a manifest ot be executed accurately.
   *
   * @return The manifest.
   */
  private static Manifest createManifest() {
    Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().put(new Attributes.Name("Agent-Class"), myName);
    manifest.getMainAttributes().put(new Attributes.Name("Can-Redefine-Classes"), "true");
    manifest.getMainAttributes().put(new Attributes.Name("Can-Retransform-Classes"), "true");
    return manifest;
  }

  /**
   * Get the bytecodes from ourselves (we're going to stream the byte code
   * of this class into the JAR). Yes this is a neat hack :-)
   *
   * @param myName - The name of the class to get the byte codes from (me!)
   * @return The bytearray containing the bytecodes of this class.
   * @throws Exception
   */
  private static byte[] getBytecodes(String myName) throws Exception {
    try (InputStream is = Log4jHotPatch.class.getResourceAsStream(myName + ".class")) {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      byte[] buf = new byte[4096];
      int len;
      if (is != null) {
        while ((len = is.read(buf)) != -1) {
          baos.write(buf, 0, len);
        }
        return baos.toByteArray();
      } else {
        throw new Exception("InputStream was null");
      }
    }
  }

  // This only works on Linux but it is harmless as it returns 'null'
  // on error and null values for the UID will be ignored later on.
  private static String getUID(String pid) {
    try {
      return Files.lines(FileSystems.getDefault().getPath("/proc/" + pid + "/status")).
        filter(l -> l.startsWith("Uid:")).
        findFirst().get().split("\\s")[1];
    } catch (Exception e) {
      return null;
    }
  }

  /**
   * Entrypoint into this Log4JHotPatch utility.
   *
   * @param args - Log4jHotPatch [<pid> [<pid> ..]]"
   * @throws Exception - Note this program can crash fairly easily so make
   *                     sure you are able to capture stderr
   */
  public static void main(String args[]) throws Exception {

    String jvmPidsToPatch[];
    if (args.length == 0) {
      logInfo("Searching for JVMs to patch...");
      logInfo("NOTE:  If your target JVMs have the -XX:+PerfDisableSharedMem flag set, then that JVM will not be detected.");
      MonitoredHost host = MonitoredHost.getMonitoredHost((String)null);
      Set<Integer> activeVms = host.activeVms();
      jvmPidsToPatch = new String[activeVms.size()];
      int count = 0;

      for (Integer pid : activeVms) {
        MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(pid.toString()));
        String mainClass = MonitoredVmUtil.mainClass(jvm, true);
        if (!myName.equals(mainClass)) {
          logInfo(pid + ": " + mainClass);
          jvmPidsToPatch[count++] = pid.toString();
        }
      }

      if (count > 0 && interactive) {
        logInfo("Patch all JVMs? (y/N) : ");
        try (BufferedReader in = new BufferedReader(new InputStreamReader(System.in))) {
            String answer = in.readLine();
            if (!"y".equalsIgnoreCase(answer)) {
                System.exit(1);
                return;
            }
        }
      } else if (count > 0) {
        logInfo("Patching all JVMs!");
      } else {
        logInfo("No JVMs to patch.");
      }
    // TODO Extract this to its on method for SRP
    } else if (args.length == 1 && ("-h".equals(args[0]) || "-help".equals(args[0]) || "--help".equals(args[0]))) {
      System.out.println("usage: Log4jHotPatch [<pid> [<pid> ..]]");
      System.exit(1);
      return;
    // TODO Sanitise these args
    } else {
      jvmPidsToPatch = args;
    }

    boolean succeeded = patchJVMs(jvmPidsToPatch);

    if (succeeded) {
      logInfo("JVMs patched successfully. Don't forget to patch permanently by upgrading to log4j 2.15.0. Goodbye!");
      System.exit(0);
    } else {
      logError("Errors occurred deploying hot patch. If you are using java 8 to run this\n" +
          "tool against JVM 11 or later, the target JVM may still be patched. Please look for a message\n" +
          "like 'Loading Java Agent (using ASM 6).' in stdout of the target JVM. Also note that JVM 17+\n" +
          "is not supported.");
      System.exit(1);
    }
  }
}
