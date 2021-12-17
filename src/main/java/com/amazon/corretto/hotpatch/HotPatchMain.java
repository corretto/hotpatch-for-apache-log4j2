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

import com.sun.tools.attach.VirtualMachine;
import sun.jvmstat.monitor.MonitoredHost;
import sun.jvmstat.monitor.MonitoredVm;
import sun.jvmstat.monitor.MonitoredVmUtil;
import sun.jvmstat.monitor.VmIdentifier;

import static com.amazon.corretto.hotpatch.Constants.LOG4J_FIXER_AGENT_VERSION;
import static com.amazon.corretto.hotpatch.Logger.log;



public class HotPatchMain {
    private static final List<String> ENTRY_POINTS = new ArrayList<>();
    static {
        ENTRY_POINTS.add(HotPatch.class.getName());

        // Add legacy entry points
        ENTRY_POINTS.add("Log4jHotPatch");
        ENTRY_POINTS.add("Log4jHotPatch17");
    }
    public static void main(String[] args) throws Exception {
        Logger.setVerbose(args);

        String pid[];
        if (args.length == 0) {
            MonitoredHost host = MonitoredHost.getMonitoredHost((String)null);
            Set<Integer> pids = host.activeVms();
            pid = new String[pids.size()];
            int count = 0;
            for (Integer p : pids) {
                MonitoredVm jvm = host.getMonitoredVm(new VmIdentifier(p.toString()));
                String mainClass = MonitoredVmUtil.mainClass(jvm, true);
                if (!ENTRY_POINTS.contains(mainClass)) {
                    log(p + ": " + mainClass);
                    pid[count++] = p.toString();
                }
            }
            if (count > 0) {
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

    private static boolean loadInstrumentationAgent(String[] pids) throws Exception {
        boolean succeeded = true;
        File jarFile = new File(HotPatchAgent.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        String agentArgs = Logger.getAgentLogArg();
        String we = getUID("self");
        for (String pid : pids) {
            if (pid != null && isValidPid(pid)) {
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
                    vm.loadAgent(jarFile.getAbsolutePath(), agentArgs);
                } catch (Exception e) {
                    succeeded = false;
                    log(e);
                    log("Error: couldn't loaded the agent into JVM process " + pid);
                    log("  Are you running as a different user (including root) than process " + pid + "?");
                    continue;
                }
                log("Successfully loaded the agent into JVM process " + pid);
                log("  Look at stdout of JVM process " + pid + " for more information");
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
