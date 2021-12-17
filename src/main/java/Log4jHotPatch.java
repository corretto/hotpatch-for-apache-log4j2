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
import java.io.File;
import java.io.InputStreamReader;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.FileSystems;
import java.security.AccessControlException;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassReader;
import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassVisitor;
import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassWriter;
import com.amazon.corretto.hotpatch.org.objectweb.asm.MethodVisitor;
import com.amazon.corretto.hotpatch.org.objectweb.asm.Opcodes;

public class Log4jHotPatch {

  // version of this agent
  private static final int log4jFixerAgentVersion = 1;

  // property name for verbose flag
  public static final String LOG4J_FIXER_VERBOSE = "log4jFixerVerbose";

  // property name for the agent version
  private static final String LOG4J_FIXER_AGENT_VERSION = "log4jFixerAgentVersion";

  private static boolean agentLoaded = false;
  private static Logger logger;
  private static Patcher patcher;
  private static ClassLoader patchLoader;

  public interface Logger {
    public void log(String msg);
    public void setVerbose(boolean verbose);
  }
  public static class SimpleLogger implements Logger {
    private static boolean verbose;
    public SimpleLogger(boolean verbose) {
      this.verbose = verbose;
    }
    @Override
    public void setVerbose(boolean verbose) {
      this.verbose = verbose;
    }
    @Override
    public void log(String msg) {
      if (verbose) {
        System.out.println(msg);
      }
    }
  }

  public interface Patcher {
    public static final int SUCCESS = 0;
    public static final int ERROR = 1;
    public String getVersion();
    public int install(String args, Instrumentation inst, Logger logger, boolean staticAgent);
    public int uninstall();
  }

  public static class EmptyPatcher implements Patcher {
    private Logger logger;
    public String getVersion() {
      return "0";
    }
    @Override
    public int install(String args, Instrumentation inst, Logger logger, boolean staticAgent) {
      this.logger = logger;
      logger.log("Installing Patcher version " + getVersion());
      return SUCCESS;
    }
    @Override
    public int uninstall() {
      logger.log("Uninstalling Patcher version " + getVersion());
      return SUCCESS;
    }
  }

  public static class PatcherV1 implements Patcher {
    private String args;
    private Instrumentation inst;
    private Logger logger;
    private ClassFileTransformer transformer;
    private static final String PATCHED_CLASS_INTERNAL = "org/apache/logging/log4j/core/lookup/JndiLookup";
    private static final String PATCHED_CLASS_EXTERNAL = PATCHED_CLASS_INTERNAL.replace('/', '.');;

    @Override
    public String getVersion() {
      return "1";
    }

    @Override
    public int install(String args, Instrumentation inst, final Logger logger, boolean staticAgent) {
      this.args = args;
      this.inst = inst;
      this.logger = logger;
      logger.log("Installing Patcher version " + getVersion());

      transformer = new ClassFileTransformer() {
          public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                  ProtectionDomain protectionDomain, byte[] classfileBuffer) {
            if (className != null && className.endsWith(PATCHED_CLASS_INTERNAL)) {
              logger.log("Transforming " + className + " (" + loader + ")");
              ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
              MethodInstrumentorClassVisitor cv = new MethodInstrumentorClassVisitor(Opcodes.ASM9, cw);
              ClassReader cr = new ClassReader(classfileBuffer);
              cr.accept(cv, 0);
              return cw.toByteArray();
            } else {
              return null;
            }
          }
        };

      if (staticAgent) {
        inst.addTransformer(transformer);
      } else {
        int patchesApplied = 0;

        inst.addTransformer(transformer, true);

        for (Class<?> c : inst.getAllLoadedClasses()) {
          String className = c.getName();
          if (className.endsWith(PATCHED_CLASS_EXTERNAL)) {
            logger.log("Patching " + c + " (" + c.getClassLoader() + ")");
            try {
              inst.retransformClasses(c);
              ++patchesApplied;
            } catch (UnmodifiableClassException uce) {
              logger.log(String.valueOf(uce));
            }
          }
        }

        if (patchesApplied == 0) {
          logger.log("Vulnerable classes were not found. This agent will continue to run " +
              "and transform the vulnerable class if it is loaded. Note that if you have shaded " +
              "or otherwise changed the package name for log4j classes, then this tool may not " +
              "find them.");
        }
      }
      return SUCCESS;
    }

    @Override
    public int uninstall() {
      inst.removeTransformer(transformer);
      // Retrans after we've removed the transformer to restore the initial class versions.
      for (Class<?> c : inst.getAllLoadedClasses()) {
        String className = c.getName();
        if (className.endsWith(PATCHED_CLASS_EXTERNAL)) {
          logger.log("Un-Patching " + c + " (" + c.getClassLoader() + ")");
          try {
            inst.retransformClasses(c);
          } catch (UnmodifiableClassException uce) {
            logger.log(String.valueOf(uce));
          }
        }
      }
      logger.log("Uninstalling Patcher version " + getVersion());
      return SUCCESS;
    }

    static class MethodInstrumentorClassVisitor extends ClassVisitor {
      public MethodInstrumentorClassVisitor(int api, ClassVisitor cv) {
        super(api, cv);
      }

      @Override
      public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
        MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
        if ("lookup".equals(name)) {
          mv = new MethodInstrumentorMethodVisitor(api, mv);
        }
        return mv;
      }
    }

    static class MethodInstrumentorMethodVisitor extends MethodVisitor implements Opcodes {

      public MethodInstrumentorMethodVisitor(int api, MethodVisitor mv) {
        super(api, mv);
      }

      @Override
      public void visitCode() {
        mv.visitCode();
        mv.visitLdcInsn("Patched JndiLookup::lookup()");
        mv.visitInsn(ARETURN);
      }
    }
  }

  // Just for testing. In reality PatcherV2 wouldn't have to extend PatcherV1
  public static class PatcherV2 extends PatcherV1 {
    @Override
    public String getVersion() {
      return "2";
    }
  }

  private static void setPatcherVersionProperty(String version) {
    // set the version of this agent in a system property so that
    // subsequent clients can read it and skip re-patching.
    try {
      System.setProperty(LOG4J_FIXER_AGENT_VERSION, version);
    } catch (AccessControlException ece) {
      logger.log("Warning: Could not record agent version in system property: " + ece.getMessage());
      logger.log("Warning: This will make it more difficult to test if agent is already loaded, but will not prevent patching");
    }
  }

  public static class AgentClassLoader extends URLClassLoader {
    public AgentClassLoader(URL[] urls) {
      super(urls);
    }
    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      // We revert the default search order and try to load everything from the agent jar file
      // to override corresponding classes which had already been loaded during a previous attach
      // of the agent.
      // The only exception to this rule are the common interfaces (i.e. "Patcher" and "Logger")
      // which must be shared between the initial agent attach and future versions of the agent
      // to prevent class cast exceptions like "Log4jHotPatch$PatcherV1 cannot be cast to Log4jHotPatch$Patcher".
      // If more common interfaces will be introduced, they must be added here as well.
      if (!name.equals("Log4jHotPatch$Patcher") && !name.equals("Log4jHotPatch$Logger")) {
        Class<?> c = findClass(name);
        if (c != null) {
          if (resolve) {
            resolveClass(c);
          }
          return c;
        }
      }
      return super.loadClass(name, resolve);
    }
    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
      // Return null instead of throwing to simplify the code
      Class<?> c;
      try {
        c = super.findClass(name);
      } catch (ClassNotFoundException cnfe) {
        c = null;
      }
      return c;
    }
  }

  public static void commonmain(String args, Instrumentation inst, boolean staticAgent) {
    // We're verbose by default
    boolean verbose = args == null || !args.contains("log4jFixerVerbose=false");
    if (agentLoaded) {
      logger.setVerbose(verbose);
      logger.log("Info: hot patch agent already loaded");
    } else {
      logger = new SimpleLogger(verbose);
      logger.log("Loading Java Agent version " + log4jFixerAgentVersion);
      agentLoaded = true;
    }

    Patcher newPatcher;
    String defaultPatcherName = EmptyPatcher.class.getName();
    if (args != null && args.contains("patcherClassName=")) {
      String[] params = args.split(",");
      for (String param : params) {
        if (param.contains("patcherClassName=")) {
          String[] keyVal = param.split("=");
          if (keyVal.length == 2) {
            defaultPatcherName = keyVal[1];
          }
        }
      }
    }
    final String patcherName = defaultPatcherName;
    try{
      String className = Log4jHotPatch.class.getName().replace('.', '/') + ".class";
      URL agentFile = ClassLoader.getSystemClassLoader().getResource(className);
      String agentFileName = agentFile.toString();
      if (agentFileName.startsWith("jar:") && agentFileName.endsWith("!/" + className)) {
        agentFileName = agentFileName.substring("jar:".length(), agentFileName.lastIndexOf("!/" + className));
        agentFile = new URL(agentFileName);
      } else {
        // This won't work if a security manager is installed
        try {
          agentFile = Log4jHotPatch.class.getProtectionDomain().getCodeSource().getLocation().toURI().toURL();
        } catch (AccessControlException ace) {
          agentFile = null;
          logger.log("Warning: can't update because we're running with a security manager (" + ace.getMessage() + ").");
          logger.log("Warning: this agent will always run with the initial patcher.");
        }
      }
      try {
        patchLoader = (agentFile == null) ?
          ClassLoader.getSystemClassLoader() : new AgentClassLoader(new URL[] { agentFile });
      } catch (AccessControlException ace) {
        // If security manger doesn't allow us to create a class (i.e. checkCreateClassLoader() fails)
        // we cant update the patcher. Fall back to the system class loader which always loads the initial patcher.
        patchLoader = ClassLoader.getSystemClassLoader();
        logger.log("Warning: can't update because we're running with a security manager (" + ace.getMessage() + ").");
        logger.log("Warning: this agent will always run with the initial patcher.");
      }
      Class<?> patcherClass = patchLoader.loadClass(patcherName);
      newPatcher = (Patcher)patcherClass.getDeclaredConstructor().newInstance();
    } catch (Exception e) {
      e.printStackTrace(System.out);
      logger.log("Error: can't load new Patcher " + patcherName);
      return;
    }

    if (patcher != null) {
      int ret = patcher.uninstall();
      if (ret == Patcher.SUCCESS) {
        logger.log("Suscessfully uninstalled old Patcher " + patcher.getVersion());
      } else {
        logger.log("Error while uninstalling old Patcher " + patcher.getVersion());
      }
    }

    int ret = newPatcher.install(args, inst, logger, staticAgent);
    if (ret == Patcher.SUCCESS) {
      logger.log("Suscessfully installed new Patcher " + newPatcher.getVersion());
      patcher = newPatcher;
      setPatcherVersionProperty(newPatcher.getVersion());
    } else {
      logger.log("Error while installing new Patcher " + newPatcher.getVersion());
      patcher = null;
      setPatcherVersionProperty("NULL");
    }
  }

  public static void agentmain(String args, Instrumentation inst) {
    commonmain(args, inst, false /* staticAgent */);
  }

  public static void premain(String args, Instrumentation inst) {
    if (args == null || !args.contains("patcherClassName")) {
      // The default patcher class. Change this if you add a new version of the Patcher.
      String defaultPatcherClass = Log4jHotPatch.PatcherV1.class.getName();
      String userPatcherClass = System.getProperty("patcherClassName");
      String patcherClass = (userPatcherClass != null) ? userPatcherClass : defaultPatcherClass;
      args = ((args == null) ? "" : args + ",") + "patcherClassName=" + patcherClass;
    }
    commonmain(args, inst, true /* staticAgent */);
  }

  private static String myName = Log4jHotPatch.class.getName();

  private static boolean loadInstrumentationAgent(String[] pids, Logger logger, String patcherClass, boolean verbose) throws Exception {
    boolean succeeded = true;
    File jarFile = new File(Log4jHotPatch.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    String we = getUID("self");
    for (String pid : pids) {
      if (pid != null) {
        try {
          // Check if we're running under the same UID like the target JVM.
          // If not, log warning as it might fail to attach.
          if (we != null && !we.equals(getUID(pid))) {
            logger.log("\nWarning: patching for JVM process " + pid + " might fail because it runs under a different user");
            logger.log("  Our uid == " + we + ", their uid == " + getUID(pid));
          }

          VirtualMachine vm = VirtualMachine.attach(pid);

          // If the target VM is already patched then skip.
          // Notice that the agent class gets loaded by the system class loader, so we
          // can't unload or update it. If we'd re-deploy the agent one more time, we'd
          // just rerun 'agentmain()' from the already loaded agent version.
          Properties props = vm.getSystemProperties();
          if (props == null) {
            logger.log("Error: could not verify 'log4jFixerAgentVersion' in JVM process " + pid);
            continue;
          }
          Patcher patcher = (Patcher)Class.forName(patcherClass).getDeclaredConstructor().newInstance();
          String oldVersionString = props.getProperty(LOG4J_FIXER_AGENT_VERSION);
          if (oldVersionString != null) {
            long oldVersion = Long.decode(oldVersionString);
            long newVersion = Long.decode(patcher.getVersion());
            if (oldVersion >= newVersion && newVersion != 0) {
              // Always allow patchin with 'EmptyPatcher' (which has version '0') to allow resetting.
              logger.log("Skipping patch for JVM process " + pid + ", patch version " + oldVersion + " >= " + newVersion);
              continue;
            }
          }

          // unpatched target VM, apply patch
          vm.loadAgent(jarFile.getAbsolutePath(), "log4jFixerVerbose=" + verbose + ",patcherClassName=" + patcherClass);
        } catch (Exception e) {
          succeeded = false;
          if (verbose) {
            e.printStackTrace(System.out);
            logger.log("Error: couldn't loaded the agent into JVM process " + pid);
            logger.log("  Are you running as a different user (including root) than process " + pid + "?");
          }
          continue;
        }
        logger.log("Successfully loaded the agent into JVM process " + pid);
        logger.log("  Look at stdout of JVM process " + pid + " for more information");
      }
    }
    return succeeded;
  }

  // This only works on Linux but it is harmless as it returns 'null'
  // on error and null values for the UID will be ignored later on.
  private static String getUID(String pid) {
    try {
      List<String> lines = Files.readAllLines(FileSystems.getDefault().getPath("/proc/" + pid + "/status"), StandardCharsets.UTF_8);
      for (String line : lines) {
        if (line.startsWith("Uid:")) {
          return line.split("\\s")[1];
        }
      }
    } catch (Exception e) {
      return null;
    }
    return null;
  }

  public static void main(String args[]) throws Exception {
    boolean verbose = Boolean.parseBoolean(System.getProperty(LOG4J_FIXER_VERBOSE, "true"));
    logger = new SimpleLogger(verbose);

    String pid[];
    if (args.length == 0) {
      MonitoredHost host = MonitoredHost.getMonitoredHost((String)null);
      Set<Integer> pids = host.activeVms();
      pid = new String[pids.size()];
      int count = 0;
      for (Integer p : pids) {
        MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(p.toString()));
        String mainClass = MonitoredVmUtil.mainClass(jvm, true);
        if (!myName.equals(mainClass)) {
          logger.log(p + ": " + mainClass);
          pid[count++] = p.toString();
        }
      }
      if (false && count > 0) {
        logger.log("Patch all JVMs? (y/N) : ");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String answer = in.readLine();
        if (!"y".equals(answer)) {
          System.exit(1);
          return;
        }
      } else if (count > 0) {
        logger.log("Patching all JVMs!");
      }
    } else if (args.length == 1 && ("-h".equals(args[0]) || "-help".equals(args[0]) || "--help".equals(args[0]))) {
      System.out.println("usage: Log4jHotPatch [<pid> [<pid> ..]]");
      System.exit(1);
      return;
    } else {
      pid = args;
    }
    // The default patcher class. Change this if you add a new version of the Patcher.
    String defaultPatcherClass = Log4jHotPatch.PatcherV1.class.getName();
    String userPatcherClass = System.getProperty("patcherClassName");
    String patcherClass = (userPatcherClass != null) ? userPatcherClass : defaultPatcherClass;
    boolean succeeded = loadInstrumentationAgent(pid, logger, patcherClass, verbose);
    if (succeeded) {
      System.exit(0);
    } else {
      logger.log("Errors occurred deploying hot patch. If you are using java 8 to run this\n" +
                 "tool against JVM 11 or later, the target JVM may still be patched. Please look for a message\n" +
                 "like 'Loading Java Agent (using ASM 6).' in stdout of the target JVM. Also note that JVM 17+\n" +
                 "are not supported.");
      System.exit(1);
    }
  }
}
