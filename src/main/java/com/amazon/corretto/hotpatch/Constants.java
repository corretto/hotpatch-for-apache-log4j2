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

public class Constants {
    // property name for the agent version. Name is kept for legacy reasons.
    public static final String LOG4J_FIXER_AGENT_VERSION = "log4jFixerAgentVersion";

    // This prefix is used to save properties with the specific version of a patcher that was installed in the vm.
    public static final String HOTPATCH_PATCHER_PREFIX = "corretto.hotpatch.";

    // Agent argument to represent the operation we want to do.
    public static final String OPERATION_ARG = "operation";

    // Agent argument with the class of the patcher we want to load via reflection.
    public static final String PATCHER_NAME_ARG = "patcherClassName";

    // Location of the jar with the patcher that will be loaded into the AgentClassLoader.
    public static final String PATCHER_JAR_ARG = "patcherJar";

    // Class name of the default patcher.
    public static final String DEFAULT_PATCHER = "com.amazon.corretto.hotpatch.patch.impl.set.Log4j2PatchSetV1";
}
