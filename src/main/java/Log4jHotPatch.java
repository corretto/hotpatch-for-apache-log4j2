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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.FileSystems;
import java.security.ProtectionDomain;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public class Log4jHotPatch {

  // version of this agent
  private static final int log4jFixerAgentVersion = 1;

  // property name for verbose flag
  public static final String LOG4J_FIXER_VERBOSE = "log4jFixerVerbose";

  // property name for the agent version
  private static final String LOG4J_FIXER_AGENT_VERSION = "log4jFixerAgentVersion";

  private static boolean verbose;

  private static boolean agentLoaded = false;

  private static boolean staticAgent = false; // Set to true if loaded as a static agent from 'premain()'

  private static void log(String message) {
    if (verbose) {
      System.out.println(message);
    }
  }

  public static void agentmain(String args, Instrumentation inst) {

    if (agentLoaded) {
      log("Info: hot patch agent already loaded");
      return;
    }

    verbose = args == null || "log4jFixerVerbose=true".equals(args);
    final int api = Opcodes.ASM9;
    log("Loading Java Agent version " + log4jFixerAgentVersion + " (using ASM" + (api >> 16) + ").");


    ClassFileTransformer transformer = new ClassFileTransformer() {
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                ProtectionDomain protectionDomain, byte[] classfileBuffer) {
          if (className != null && className.endsWith("org/apache/logging/log4j/core/lookup/JndiLookup")) {
            log("Transforming " + className + " (" + loader + ")");
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
            MethodInstrumentorClassVisitor cv = new MethodInstrumentorClassVisitor(api, cw);
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
        if (className.endsWith("org.apache.logging.log4j.core.lookup.JndiLookup")) {
          log("Patching " + c + " (" + c.getClassLoader() + ")");
          try {
            inst.retransformClasses(c);
            ++patchesApplied;
          } catch (UnmodifiableClassException uce) {
            log(String.valueOf(uce));
          }
        }
      }

      if (patchesApplied == 0) {
        log("Vulnerable classes were not found. This agent will continue to run " +
            "and transform the vulnerable class if it is loaded. Note that if you have shaded " +
            "or otherwise changed the package name for log4j classes, then this tool may not " +
            "find them.");
      }
    }

    agentLoaded = true;

    // set the version of this agent in a system property so that
    // subsequent clients can read it and skip re-patching.
    try {
      System.setProperty(LOG4J_FIXER_AGENT_VERSION, String.valueOf(log4jFixerAgentVersion));
    } catch (Exception e) {
      log("Warning: Could not record agent version in system property: " + e.getMessage());
      log("Warning: This will make it more difficult to test if agent is already loaded, but will not prevent patching");
    }
  }

  public static void premain(String args, Instrumentation inst) {
    staticAgent = true;
    agentmain(args, inst);
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

  private static String myName = Log4jHotPatch.class.getName();

  private static boolean loadInstrumentationAgent(String[] pids) throws Exception {
    boolean succeeded = true;
    File jarFile = new File(Log4jHotPatch.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    String we = getUID("self");
    for (String pid : pids) {
      if (pid != null) {
        try {
          // Check if we're running under the same UID like the target JVM.
          // If not, log warning as it might fail to attach.
          if (we != null && !we.equals(getUID(pid))) {
            log("\nWarning: patching for JVM process " + pid + " might fail because it runs under a different user");
            log("  Our uid == " + we + ", their uid == " + getUID(pid));
          }

          VirtualMachine vm = VirtualMachine.attach(pid);

          // If the target VM is already patched then skip.
          // Notice that the agent class gets loaded by the system class loader, so we
          // can't unload or update it. If we'd re-deploy the agent one more time, we'd
          // just rerun 'agentmain()' from the already loaded agent version.
          Properties props = vm.getSystemProperties();
          if (props == null) {
            log("Error: could not verify 'log4jFixerAgentVersion' in JVM process " + pid);
            continue;
          }
          String version = props.getProperty(LOG4J_FIXER_AGENT_VERSION);
          if(version != null) {
            log("Skipping patch for JVM process " + pid + ", patch version " + version + " already applied");
            continue;
          }

          // unpatched target VM, apply patch
          vm.loadAgent(jarFile.getAbsolutePath(), "log4jFixerVerbose=" + verbose);
        } catch (Exception e) {
          succeeded = false;
          if (verbose) {
            e.printStackTrace(System.out);
            log("Error: couldn't loaded the agent into JVM process " + pid);
            log("  Are you running as a different user (including root) than process " + pid + "?");
          }
          continue;
        }
        log("Successfully loaded the agent into JVM process " + pid);
        log("  Look at stdout of JVM process " + pid + " for more information");
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
    verbose = Boolean.parseBoolean(System.getProperty(LOG4J_FIXER_VERBOSE, "true"));

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
          log(p + ": " + mainClass);
          pid[count++] = p.toString();
        }
      }
      if (false && count > 0) {
        log("Patch all JVMs? (y/N) : ");
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String answer = in.readLine();
        if (!"y".equals(answer)) {
          System.exit(1);
          return;
        }
      } else if (count > 0) {
        log("Patching all JVMs!");
      }
    } else if (args.length == 1 && ("-h".equals(args[0]) || "-help".equals(args[0]) || "--help".equals(args[0]))) {
      System.out.println("usage: Log4jHotPatch [<pid> [<pid> ..]]");
      System.exit(1);
      return;
    } else {
      pid = args;
    }
    boolean succeeded = loadInstrumentationAgent(pid);
    if (succeeded) {
      System.exit(0);
    } else {
      log("Errors occurred deploying hot patch. If you are using java 8 to run this\n" +
          "tool against JVM 11 or later, the target JVM may still be patched. Please look for a message\n" +
          "like 'Loading Java Agent (using ASM 6).' in stdout of the target JVM. Also note that JVM 17+\n" +
          "are not supported.");
      System.exit(1);
    }
  }
}
