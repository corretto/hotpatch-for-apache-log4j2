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

package com.amazon.corretto.hotpatch.interfaces;

import java.lang.instrument.Instrumentation;
import java.util.Map;

/**
 * A patcher is a class capable of applying and unapplying a patch to the target VM. A name/version/result tuple is stored
 * into the target VM properties in order to decide whether further attempts to apply the patch are needed.
 * This interface acts as a boundary between classloaders. It will be present in the System ClassLoader of the VM
 * we are patching, but its implementations may be loaded by {@link com.amazon.corretto.hotpatch.AgentClassLoader}.
 *
 * Modifying this interface will cause errors if we attach to a VM that has a previous version already loaded.
 */
public interface Patcher {
    int SUCCESS = 0;
    int ERROR = 1;

    /**
     * Name of the patcher we want to install. The tool will only allow one patcher for a given name to be installed.
     * @return name of the Patcher
     */
    String getName();

    /**
     * Version of the patcher. The tool will not install a patcher if a patcher with the same or higher version is
     * already installed. If a version of the patcher with a lower version is present, it will be uninstalled before the
     * new one is installed.
     * @return an integer representing the version
     */
    int getVersion();

    /**
     * A brief description of what this patch does.
     * @return brief description of what this patch does
     */
    String getShortDescription();


    /**
     * A more detailed version explaining exactly the changes this patch does.
     * @return A more detailed version explaining exactly the changes this patch does
     */
    String getFullDescription();

    /**
     * Install this patcher into the target Virtual Machine.
     * @param args Map representing the arguments that were received by the agent.
     * @param asmApiVersion version of ASM to use.
     * @param inst The instance of instrumentation the agent is working with
     * @param logger A simple logger instance
     * @param staticAgent true if we were installed as a java agent on startup, false if we are attaching to a VM
     * @return either {@link #SUCCESS} or {@link #ERROR} depending on the installation result
     */
    int install(Map<String, String> args, int asmApiVersion, Instrumentation inst, Logger logger, boolean staticAgent);

    /**
     * Uninstall the patcher from the target virtual vm
     * @return either {@link #SUCCESS} or {@link #ERROR} depending on the uninstallation result.
     */
    int uninstall();
}
