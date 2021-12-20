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

package com.amazon.corretto.hotpatch;

import java.lang.instrument.Instrumentation;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.AccessControlException;
import java.util.HashMap;
import java.util.Map;

import com.amazon.corretto.hotpatch.interfaces.Logger;
import com.amazon.corretto.hotpatch.interfaces.Patcher;
import com.amazon.corretto.hotpatch.org.objectweb.asm.Opcodes;

import static com.amazon.corretto.hotpatch.Constants.*;

/**
 * This is the main class of our agent that will apply the different patchers. One of the most important parts about
 * this class is that it will always be loaded into the SystemClassloader, future executions of the HotPatcher that are
 * attached into the VM will still be executed through this class, by calling the
 * {@link #agentmain(String, Instrumentation)} method.
 *
 * For that reason, this class does not apply the patches directly. If that were the case, it would not be possible to
 * update a patch without having a different version of this class, with a different name, so it would be loaded as a
 * different agent. The solution is that this class attempts to load a {@link Patcher} class on its own custom
 * classloader and cedes control to it for installation and uninstallation. In order to avoid issues of classes already
 * loaded, the custom classLoader will load classes from the jar first, and only if not found inherit from the parent
 * classloader. The exception to this rule is classes in the {@code com.amazon.corretto.hotpatch.interfaces} package,
 * like the {@link Patcher} and {@link Logger}.
 *
 * Copies of this class need to be backwards compatible when connecting to VMs running older versions of it, but older
 * versions of the class may not be able to function properly if a newer version is already attached. To prevent
 * compatibility problems a SystemProperty {@link Constants#LOG4J_FIXER_AGENT_VERSION} is set with the version of this
 * agent. That property can be checked before installing the agent in an existing VM.
 *
 * What patcher to install and the location of the jar where the patcher is present (often bundled in the same one as
 * the agent) are passed as parameters to the agent. If the agent is not able to locate or load the jar using its
 * custom classloader, the SystemClassloader will be used, mirroring the behavior of previous versions of the tool. If
 * the patcher to be loaded cannot be determined, the default patcher
 * {@link com.amazon.corretto.hotpatch.patch.impl.set.Log4j2PatchSetV1} will be applied, which applies the same
 * class transformation as older versions of this tool.
 */
public class HotPatchAgent {
  // version of this agent, it will be stored in a property named {@link Constants#LOG4J_FIXER_AGENT_VERSION}
  public static final int HOTPATCH_AGENT_VERSION = 2;

  // used to know if we are the first time the agent is being loaded
  private static boolean agentLoaded = false;

  // a default implementation of the logger. By default, set to verbose, but information regarding verbosity will be set
  // before any message is executed. Subsequent installations of the agent will not create new loggers, but they will
  // update it to match the new configuration.
  private static final LoggerImpl logger = new LoggerImpl();
  private static final Map<String, Patcher> appliedPatchers = new HashMap<>();

  // Some patchers may load ASM from their own jar, others will use the version already loaded if an agent is already
  // present. We pick the version of ASM included with the first agent attached as the one to use.
  public static int asmApiVersion() {
    return Opcodes.ASM9;
  }
  
  /**
   * This is the entry point when the agent is loaded during startup. The main difference in this scenario will be that
   * we only need to load our transformers, but there is no need to retransform existing classes as they have not been
   * loaded yet. Additionally, we may not receive parameters as agent args, but as SystemProperties.
   * @param args String representing the different arguments for the agent.
   * @param inst An instance of instrumentation that will be used to apply the different patchers.
   */
  public static void premain(String args, Instrumentation inst) {
    if (args == null || !args.contains(PATCHER_NAME_ARG)) {
      // The default patcher class. Change this if you add a new version of the Patcher.
      String userPatcherClass = System.getProperty(PATCHER_NAME_ARG);
      String patcherClass = (userPatcherClass != null) ? userPatcherClass : DEFAULT_PATCHER;
      args = ((args == null) ? "" : args + ",") + PATCHER_NAME_ARG + patcherClass;
    }
    commonmain(args, inst, true /* staticAgent */);
  }

  /**
   * This is the entry point when the agent is loaded after attaching to a running VM. Multiple agents being attached
   * will cause multiple executions of this method. Even if we attach a newer agent, the version of the method to
   * execute will be the one that was loaded first.
   * @param args String representing the different arguments for the agent.
   * @param inst An instance of instrumentation that will be used to apply the different patchers.
   */
  public static void agentmain(String args, Instrumentation inst) {
    commonmain(args, inst, false /* staticAgent */);
  }

  /**
   * This is the main method of the agent, and it is invoked in both scenarios, when we are attached to a running VM or
   * when we are loaded during startup.
   * @param args String representing the different arguments passed to the agent.
   * @param inst An instance of instrumentation that will be used to apply the different patchers.
   * @param staticAgent True if we are loaded as an agent during startup, false if we are being attached.
   */
  private static void commonmain(String args, Instrumentation inst, boolean staticAgent) {
    logger.setVerbose(args);
    if (agentLoaded) {
      logger.log(Logger.INFO, "hot patch agent already loaded");
    } else {
      logger.log(Logger.INFO, "Loading Java Agent version " + HOTPATCH_AGENT_VERSION);
      agentLoaded = true;
      setAgentVersionProperty();
    }

    Map<String, String> processedArgs = processArgs(args);
    if (processedArgs.containsKey("uninstall")) {
      uninstallPatcher(processedArgs.get("uninstall"), true);
    } else {
      installPatcher(inst, staticAgent, processedArgs);
    }
  }

  private static void installPatcher(Instrumentation inst, boolean staticAgent, Map<String, String> processedArgs) {
    String patcherName = getPatcherClassName(processedArgs);
    Patcher newPatcher;

    try {
      URL patcherJar = getPatcherJar(processedArgs);
      newPatcher = loadPatcher(patcherName, patcherJar);
    } catch (Exception e) {
      logger.log(Logger.ERROR, "Can't load new Patcher " + patcherName);
      return;
    }

    // We have been able to load our new Patcher, but before we go on, we have to check and uninstall the previously
    // installed patcher.
    uninstallPatcher(newPatcher.getName(), false);

    // Everything is ready, install the new patcher
    int ret = newPatcher.install(processedArgs, asmApiVersion(), inst, logger, staticAgent);
    if (ret == Patcher.SUCCESS) {
      logger.log("Successfully installed new Patcher " + newPatcher.getVersion());
      appliedPatchers.put(newPatcher.getName(), newPatcher);
      setPatcherVersionProperty(newPatcher.getName(), String.valueOf(newPatcher.getVersion()));
    } else {
      logger.log("Error while installing new Patcher " + newPatcher.getVersion());
      appliedPatchers.remove(newPatcher.getName());
      setPatcherVersionProperty(newPatcher.getName(), null);
    }
  }

  /**
   * Uninstalls a patcher. There are two reasons we may want to uninstall a patcher. We either got a request for it
   * directly as a command line argument, or we are uninstalling this patcher because we are replacing it with a newer
   * version. When we are not replacing the patcher, we want to clear the associated system property, so the patcher can
   * be applied in the future. When we are updating the patcher, the process of installing will take care of changing
   * the value.
   * @param patcherName Name of the patcher we want to uninstall.
   * @param clearProperty If true, the associated system property will be cleared
   */
  private static void uninstallPatcher(String patcherName, boolean clearProperty) {
    Patcher oldPatcher = appliedPatchers.remove(patcherName);
    if (oldPatcher != null) {
      int ret = oldPatcher.uninstall();
      if (ret == Patcher.SUCCESS) {
        logger.log("Successfully uninstalled old Patcher " + oldPatcher.getVersion());
      } else {
        logger.log("Error while uninstalling old Patcher " + oldPatcher.getVersion());
      }
    }
    if (clearProperty) {
      setPatcherVersionProperty(patcherName, null);
    }
  }

  /**
   * Attempt to load a patcher. If possible, this patcher will be read using a custom classloader from a jar file. If
   * that is not possible, the patcher will be read from the System ClassLoader, limiting this to only the patchers that
   * were bundled with the first instance of the agent that was loaded.
   * @param patcherClassName Name of the class of the patcher to load.
   * @param patcherJar Location of the jar from which we will try to load the patch
   * @return The instance of patcher requested
   * @throws Exception Reflection and ClassLoader related exceptions can be thrown by this method. Multiple things can
   *                   go wrong.
   */
  private static Patcher loadPatcher(final String patcherClassName, final URL patcherJar) throws Exception {
    ClassLoader patchLoader;
    try {
      patchLoader = (patcherJar == null) ?
              ClassLoader.getSystemClassLoader() : new AgentClassLoader(new URL[] { patcherJar });
    } catch (AccessControlException ace) {
      // If security manger doesn't allow us to create a class (i.e. checkCreateClassLoader() fails)
      // we cant update the patcher. Fall back to the system class loader which always loads the initial patcher.
      patchLoader = ClassLoader.getSystemClassLoader();
      logger.log(Logger.WARN, "Can't update because we're running with a security manager (" + ace.getMessage() + ").");
      logger.log(Logger.WARN, "This agent will always run with the initial patcher.");
    }
    Class<?> patcherClass = patchLoader.loadClass(patcherClassName);
    return (Patcher)patcherClass.getDeclaredConstructor().newInstance();
  }

  /**
   * Agent arguments are received as a single string. This helper method will translate that into a Map of strings.
   * Commas are used to represent different keys for the map, while equals represents the separation between a key and
   * its value. If multiple equals are present, only the first one will be considered a separator.
   * It is possible to have parameters with no value. In that case, an empty string will be used as the value for the
   * corresponding key in the map.
   * @param args The string will all the arguments received by the agent.
   * @return A map that represents the different arguments.
   */
  private static Map<String, String> processArgs(String args) {
    Map<String, String> processedArgs = new HashMap<>();
    if (args != null) {
      for (String arg : args.split(",")) {
        int equalPosition = arg.indexOf("=");
        if (equalPosition == -1) {
          processedArgs.put(arg, "");
        } else {
          processedArgs.put(arg.substring(0, equalPosition), arg.substring(equalPosition + 1));
        }
      }
    }
    return processedArgs;
  }

  /**
   * Get the name of the patcher we want to install or uninstall. This will be read from the agent args, and if not
   * present, the default patcher will be used.
   * @param processedArgs Map of agent args split into key value pairs.
   * @return String with the class name of the Patcher we want to operate on
   */
  private static String getPatcherClassName(Map<String, String> processedArgs) {
    if (processedArgs.containsKey(PATCHER_NAME_ARG)) {
      return processedArgs.get(PATCHER_NAME_ARG);
    } else {
      return DEFAULT_PATCHER;
    }
  }

  /**
   * The objective of this function is to locate a jar that we can load into our own ClassLoader with the actual patcher
   * code. Three different strategies are used to get that jar path:
   * - Based on the args received by the agent (this should always be the case when we attach).
   * - Based on the location of the AgentClass the SystemClassloader sees.
   * - By checking getProtectionDomain().getCodeSource().getLocation() (can fail if a Security Manager is present).
   *
   * If we fail all these strategies, we will not be able to use a custom classloader to load the patch, and we will
   * have to use the Application one.
   * @param processedArgs Map with the arguments that were passed to the agent already split into key value pairs.
   * @return A URL for the jar from which we should load the patcher, null if we weren't able to get a jar location.
   */
  private static URL getPatcherJar(Map<String, String> processedArgs) {
    // Option 1: Get the jar location from an argument
    if (processedArgs.containsKey(Constants.PATCHER_JAR_ARG)) {
      try {
        return new URL(processedArgs.get(Constants.PATCHER_JAR_ARG));
      } catch (MalformedURLException mue) {
        // Unable to get the jar from command line arg, fallthrough
      }
    }

    // Option 2, try to derive our own jar location from our path
    String className = HotPatchAgent.class.getName().replace('.', '/') + ".class";
    URL patcherJar = ClassLoader.getSystemClassLoader().getResource(className);
    try {
      String agentFileName = patcherJar.toString();
      // If we have been loaded from a jar we should be able to see the jar path in the class path
      if (agentFileName.startsWith("jar:") && agentFileName.endsWith("!/" + className)) {
        agentFileName = agentFileName.substring("jar:".length(), agentFileName.lastIndexOf("!/" + className));
        return new URL(agentFileName);
      }
    } catch (MalformedURLException | NullPointerException mue) {
      logger.log(Logger.WARN, "Unable to derive jar location from the agent class: " + mue.getMessage());
    }

    // Option 3, get the location through the protection domain, although this can fall if we have a security manager
    // installed
    try {
      patcherJar = HotPatchAgent.class.getProtectionDomain().getCodeSource().getLocation().toURI().toURL();
    } catch (AccessControlException ace) {
      patcherJar = null;
      logger.log(Logger.WARN, "Can't update because we're running with a security manager (" + ace.getMessage() + ").");
      logger.log(Logger.WARN, "This agent will always run with the initial patcher.");
    } catch (URISyntaxException | MalformedURLException use) {
      patcherJar = null;
      logger.log(Logger.WARN, "Unable to obtain the patcher jar location  (" + use.getMessage() + ").");
      logger.log(Logger.WARN, "This agent will always run with the initial patcher.");
    }
    return patcherJar;
  }

  /**
   * Set the version of the agent that is currently loaded in a SystemProperty. This can be done to prevent older
   * versions of the agent to attach, as they may lead to errors. It may not be possible to set this if a
   * SecurityManager is installed.
   */
  private static void setAgentVersionProperty() {
    // set the version of this agent in a system property to prevent agents with an older version to attach.
    try {
      System.setProperty(Constants.LOG4J_FIXER_AGENT_VERSION, String.valueOf(HOTPATCH_AGENT_VERSION));
    } catch (AccessControlException ece) {
      logger.log(Logger.WARN, "Could not record agent version in system property: " + ece.getMessage());
      logger.log(Logger.WARN, "This will make it more difficult to test if agent is already loaded, " +
              "but will not prevent patching");
    }
  }

  /**
   * Set the version of the patcher that was applied as a system property. Before another agent attaches, it will check
   * if the version of the patch it is going to apply is already there. This operation may do nothing if a
   * SecurityManager is present.
   * @param name Name of the patcher for which we want to store a property.
   * @param version Version of the patcher to store. If null, the property will be cleared.
   */
  private static void setPatcherVersionProperty(String name, String version) {
    try {
      if (version == null) {
        System.clearProperty(HOTPATCH_PATCHER_PREFIX + name);
      } else {
        System.setProperty(HOTPATCH_PATCHER_PREFIX + name, version);
      }
    } catch (AccessControlException ece) {
      logger.log(Logger.WARN, "Could not record the patcher version in a system property: " + ece.getMessage());
      logger.log(Logger.WARN, "This will make it more difficult to test if the patcher was already applied, " +
              "but will not prevent patching");
    }
  }
}
