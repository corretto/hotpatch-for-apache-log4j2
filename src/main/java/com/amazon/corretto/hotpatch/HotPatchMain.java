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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import com.amazon.corretto.hotpatch.interfaces.Patcher;
import com.amazon.corretto.hotpatch.patch.impl.set.Log4j2PatchSetV0;
import com.amazon.corretto.hotpatch.patch.impl.set.Log4j2PatchSetV1;
import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

import static com.amazon.corretto.hotpatch.Constants.*;

public class HotPatchMain {
    private static LoggerImpl logger = new LoggerImpl(new String[]{});

    private static final List<String> ENTRY_POINTS = new ArrayList<>();
    static {
        ENTRY_POINTS.add(HotPatchMain.class.getName());

        // Add legacy entry points
        ENTRY_POINTS.add("Log4jHotPatch");
        ENTRY_POINTS.add("Log4jHotPatch17");
    }

    private static final List<Patcher> KNOWN_PATCHERS = new ArrayList<>();
    static {
        KNOWN_PATCHERS.add(new Log4j2PatchSetV0());
        KNOWN_PATCHERS.add(new Log4j2PatchSetV1());
    }

    private static final String DEFAULT_PATCHER = Log4j2PatchSetV1.class.getName();

    public static void main(String[] args) throws Exception {
        logger = new LoggerImpl(args);

        // Quick check if this is a request for help
        checkHelpParams(args);

        List<String> pids = new ArrayList<>();
        List<String> nonPids = new ArrayList<>();
        for (String arg : args) {
            if (isValidPid(arg)) {
                pids.add(arg);
            } else {
                nonPids.add(arg);
            }
        }

        String operation = args.length > 0 ? args[0] : "install";
        switch (operation) {
            case "uninstall":
                uninstall(pids, nonPids);
                break;
            case "help":
                printHelp();
                break;
            case "info":
                printPatcherInfo(nonPids);
                break;
            case "version":
                printVersion();
                break;
            case "install":
            default:
                install(pids, nonPids);
        }


    }

    private static void install(List<String> pids, List<String> nonPidArgs) throws Exception {
        String patcherClass = DEFAULT_PATCHER;

        // Try to get a well known patcher name as a positional parameter
        if (nonPidArgs.size() > 1 && nonPidArgs.get(0).equals("install")) {
            String patcherName = nonPidArgs.get(1);
            String patcherVersion = null;
            if (patcherName.contains("#")) {
                patcherVersion = patcherName.substring(patcherName.indexOf("#") + 1);
                patcherName = patcherName.substring(0, patcherName.indexOf("#"));
            }
            Patcher chosenPatcher = null;
            for (Patcher patcher : KNOWN_PATCHERS) {
                if (patcher.getName().equals(patcherName)) {
                    // Check if we are aiming for a specific version
                    if (patcherVersion != null) {
                        if (String.valueOf(patcher.getVersion()).equals(patcherVersion)) {
                            patcherClass = patcher.getClass().getName();
                            break;
                        }
                    } else {
                        // We are not looking for a specific version, selecting the higher version possible
                        if (chosenPatcher == null || chosenPatcher.getVersion() < patcher.getVersion()) {
                            chosenPatcher = patcher;
                        }
                    }
                }
            }
            if (chosenPatcher != null) {
                patcherClass = chosenPatcher.getClass().getName();
            }
        }

        // Try to get a fully class name from --patcherClassName=
        for (String arg : nonPidArgs) {
            if (arg.startsWith("--patcherClassName=")) {
                patcherClass = arg.substring(arg.indexOf("=" + 1));
            }
        }

        if (pids.size() == 0) {
            pids.addAll(getAllTargetPids());
        }
        boolean succeeded = loadInstrumentationAgent(pids, patcherClass, nonPidArgs);
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

    private static void uninstall(List<String> pids, List<String> nonPids) {
        logger.log("Operation not yet supported.");
        System.exit(1);
    }

    /**
     * If we detect no pid on the arguments, we query the VM for all the pids belonging to java processes.
     * To avoid unnecessary pids, we filter out those belonging to this tool.
     * @return A list with all the pids we should attempt to attach to.
     */
    private static List<String> getAllTargetPids() throws Exception {
        MonitoredHost host = MonitoredHost.getMonitoredHost((String)null);
        Set<Integer> allPids = host.activeVms();
        List<String> targetPids = new ArrayList<>();
        for (Integer p : allPids) {
            MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(p.toString()));
            String mainClass = MonitoredVmUtil.mainClass(jvm, true);
            if (!ENTRY_POINTS.contains(mainClass)) {
                logger.log(p + ": " + mainClass);
                targetPids.add(p.toString());
            }
        }
        if (targetPids.size() > 0) {
            logger.log("Patching all JVMs!");
        }
        return targetPids;
    }

    private static void checkHelpParams(String[] args) {
        for (String arg : args) {
            if (arg.equals("help") || arg.equals("-h") || arg.equals("--help") || arg.equals("-help")) {
                printHelp();
            }
        }
    }

    private static void printHelp() {
        logger.log("usage: Log4jHotPatch [<operation>] [<parameters>] [<pid> [<pid> ..]]");
        logger.log("Operations:");
        logger.log("  install [<patcher>] [<parameters>] [<pid> [<pid> ..]]   - installs a patcher into the target VM");
        //logger.log("  uninstall [<patcher>] [<parameters>] [<pid> [<pid> ..]] - uninstalls a patcher from the target VM");
        logger.log("  info [<patcher>]                                        - show information about bundled patchers");
        logger.log("  version                                                 - show version information");
        logger.log("  help                                                    - show this help");
        logger.log("Default operation: install");
        logger.log("Parameters");
        logger.log("  -q | --quiet                             - minimize the amount of information logged");
        logger.log("  --dry-run                                - do not attach, but print the actions that will be performed");
        logger.log("  --patcherClassName=<className>           - attempt to install the specific class as a patcher");
        logger.log("  --skipAgentVersionCheck=true             - attach to the target VM even if there is an agent already present with a higher version");
        logger.log("  --skipPatcherVersionCheck=true           - apply the patcher even if a patcher with the same or higher version is present");
        System.exit(0);
    }

    /**
     * Print version related information and exit.
     */
    private static void printVersion() {
        String name = HotPatchMain.class.getPackage().getImplementationTitle();
        String vendor = HotPatchMain.class.getPackage().getImplementationVendor();
        String version = HotPatchMain.class.getPackage().getImplementationVersion();
        System.err.println(name + " by " + vendor);
        System.err.println("Version: " + version);
        System.err.println("Agent version: " + HotPatchAgent.HOTPATCH_AGENT_VERSION);
        System.exit(0);
    }

    /**
     * Show information about the patchers the tool is aware of and exit.
     */
    private static void printPatcherInfo(List<String> nonPidArgs) {
        logger.log("Printing patcher info:");
        String patcherName = null;
        if (nonPidArgs.size() > 1 && !nonPidArgs.get(1).startsWith("-")) {
            patcherName = nonPidArgs.get(1);
        }
        for (Patcher patcher : KNOWN_PATCHERS) {
            if (patcherName == null) {
                logger.log("  " + patcher.getName() + "#" + patcher.getVersion() + ": " +  patcher.getShortDescription());
            } else if (patcherName.startsWith(patcher.getName())) {
                logger.log(patcher.getFullDescription());
            }
        }
        if (patcherName == null) {
            logger.log("Use \"info <patcher>\" to get more information about a patcher" );
        }
        System.exit(0);
    }

    private static boolean loadInstrumentationAgent(List<String> pids, String patcherClass, List<String> nonPidArgs) throws Exception {
        boolean succeeded = true;
        boolean skipAgentVersionCheck = nonPidArgs.contains("--skipAgentVersionCheck=true");
        boolean skipPatcherVersionCheck = nonPidArgs.contains("--skipPatcherVersionCheck=true");
        boolean dryRun = nonPidArgs.contains("--dry-run");
        File jarFile = new File(HotPatchMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
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

                    // First we verify the version of the agent. We want to make certain we are not connecting to a
                    // version of the agent that might have unknown code in the 'agentmain()'. If a newer agent is
                    // deployed, that jar should be used to attach again and apply any other patches.
                    if (!skipAgentVersionCheck) {
                        String oldVersionString = props.getProperty(LOG4J_FIXER_AGENT_VERSION);
                        if (oldVersionString != null) {
                            long oldVersion = Long.decode(oldVersionString);
                            long newVersion = HotPatchAgent.HOTPATCH_AGENT_VERSION;
                            if (oldVersion > newVersion) {
                                logger.log("Skipping patch for JVM process " + pid + ", installed agent version "
                                        + oldVersion + " > " + newVersion);
                                continue;
                            }
                        }
                    }
                    Patcher patcher;
                    // Now we verify the version of the patcher. If there is already a version of this patcher
                    // installed, we will only want to continue if we are about to install a version that is higher.
                    // The exception to this is version 0, which should always be an empty patcher that applies no
                    // transformations.
                    if (!skipPatcherVersionCheck) {
                        patcher = (Patcher)Class.forName(patcherClass).getDeclaredConstructor().newInstance();
                        String oldVersionString = props.getProperty(HOTPATCH_PATCHER_PREFIX + patcher.getName());
                        if (oldVersionString != null) {
                            long oldVersion = Long.decode(oldVersionString);
                            long newVersion = patcher.getVersion();
                            if (newVersion == 0) {
                                logger.log("Applying patcher " + patcher.getName()
                                        + " version 0 to clear transformations");
                            } else if (oldVersion >= newVersion) {
                                logger.log("Skipping patch for JVM process " + pid + ", installed patcher "
                                        + patcher.getName() + " "  + oldVersion + " >= " + newVersion);
                                continue;
                            }
                        }
                    }

                    // We are good to go on our multiple version checks.
                    String options = OPERATION_ARG + "=install";
                    options += "," + PATCHER_NAME_ARG + "=" + patcherClass;
                    options += "," + PATCHER_JAR_ARG + "=" + jarFile.getAbsolutePath();
                    options += "," + logger.getAgentLogArg();
                    if (dryRun) {
                        System.out.println("Will attach agent to process with pid: " + pid);
                        System.out.println("options: " + options);
                    } else {
                        vm.loadAgent(jarFile.getAbsolutePath(), options);
                    }
                } catch (Exception e) {
                    succeeded = false;
                    logger.log(e);
                    logger.log("Error: couldn't loaded the agent into JVM process " + pid);
                    logger.log("  Are you running as a different user (including root) than process " + pid + "?");
                    continue;
                }
                if (!dryRun) {
                    logger.log("Successfully loaded the agent into JVM process " + pid);
                    logger.log("  Look at stdout of JVM process " + pid + " for more information");
                }
            }
        }
        return succeeded;
    }

    // This only works on Linux, but it is harmless as it returns 'null'
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

    private static boolean isValidPid(String pidStr) {
        try {
            int pid = Integer.parseInt(pidStr);
            return pid >= 0;
        } catch (NumberFormatException nfe) {
            return false;
        }
    }
}
