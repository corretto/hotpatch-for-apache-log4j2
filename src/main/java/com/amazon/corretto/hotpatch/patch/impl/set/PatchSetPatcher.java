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

package com.amazon.corretto.hotpatch.patch.impl.set;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.amazon.corretto.hotpatch.interfaces.Logger;
import com.amazon.corretto.hotpatch.interfaces.Patcher;
import com.amazon.corretto.hotpatch.patch.ClassTransformerHotPatch;

/**
 * A class that is capable of applying multiple {@link ClassTransformerHotPatch} together as a single patcher.
 */
public abstract class PatchSetPatcher implements Patcher {
    private Instrumentation instrumentation;
    private Logger logger;
    private ClassFileTransformer transformer;

    protected abstract List<ClassTransformerHotPatch> getPatches();

    @Override
    public int install(final Map<String, String> args, final int asmApiVersion, final Instrumentation instrumentation,
                       final Logger logger, final boolean staticAgent) {
        this.instrumentation = instrumentation;
        this.logger = logger;

        this.transformer = new PatchSetTransformer(getPatches(), asmApiVersion, logger);

        if (staticAgent) {
            // As we are being installed during startup, we don't care about retransforming. The transformer will
            // patch the classes as they are being loaded.
            instrumentation.addTransformer(transformer);
        } else {
            // We are being attached to a running VM, we need to retransform the classes targeted by the patches that
            // have already been loaded.
            instrumentation.addTransformer(transformer, true);

            boolean patchesApplied = false;
            for (Class<?> c : instrumentation.getAllLoadedClasses()) {
                String className = c.getName();
                for (ClassTransformerHotPatch patch : getPatches()) {
                    if (patch.isTargetClass(className)) {
                        logger.log("Patching + " + className + " (" + c.getClassLoader() + ") with patch "
                                + patch.getName());
                        try {
                            instrumentation.retransformClasses(c);
                            patchesApplied = true;
                        } catch (UnmodifiableClassException uce) {
                            logger.log(String.valueOf(uce));
                        }
                    }
                }
            }

            if (!patchesApplied) {
                logger.log("Vulnerable classes were not found. This agent will continue to run " +
                        "and transform the target classes if they are loaded. Note that if you have shaded " +
                        "or otherwise changed the package name for target classes, then this tool may not " +
                        "find them.");
            }
        }

        return Patcher.SUCCESS;
    }

    @Override
    public int uninstall() {
        instrumentation.removeTransformer(transformer);
        // Retransform after we've removed the transformer to restore the initial class versions.
        for (Class<?> c : instrumentation.getAllLoadedClasses()) {
            String className = c.getName();
            for (ClassTransformerHotPatch patch : getPatches()) {
                if (patch.isTargetClass(className)) {
                    logger.log("Un-Patching " + c + " (" + c.getClassLoader() + ") of " + patch.getName());
                    try {
                        instrumentation.retransformClasses(c);
                    } catch (UnmodifiableClassException uce) {
                        logger.log(String.valueOf(uce));
                    }
                }
            }
        }
        logger.log("Uninstalled Patcher: " + getName() + ". Version: " + getVersion());
        return SUCCESS;
    }

    /**
     * A detailed description for this PatchSet that includes the description of the individual patches that will be
     * applied.
     * @return A detailed description for this PatchSet that includes the description of the individual patches that
     *         will be applied.
     */
    @Override
    public String getFullDescription() {
        StringBuilder sb = new StringBuilder();
        sb.append(getName()).append("#").append(getVersion()).append(":").append(System.lineSeparator());
        sb.append("  ").append(getShortDescription()).append(System.lineSeparator());
        sb.append("  Applies the following patches:").append(System.lineSeparator());
        for (ClassTransformerHotPatch patch : getPatches()) {
           sb.append("    ").append(patch.getName()).append(": ").append(patch.getDescription())
                   .append(System.lineSeparator());
        }
        return sb.toString();
    }

    private static class PatchSetTransformer implements ClassFileTransformer {
        private final Logger logger;
        private final int asmApiVersion;
        private final List<ClassTransformerHotPatch> patches;

        public PatchSetTransformer(final List<ClassTransformerHotPatch> patches, final int asmApiVersion,
                                   final Logger logger) {
            this.asmApiVersion = asmApiVersion;
            this.logger = logger;
            this.patches = patches;
        }

        @Override
        public byte[] transform(final ClassLoader loader, final String className,
                                final Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
                                byte[] classfileBuffer) {
            if (className != null) {
                for (ClassTransformerHotPatch patch : patches) {
                    if (patch.isTargetClass(className)) {
                        logger.log("Transforming + " + className + " (" + loader + ") with patch "
                                + patch.getName());
                        return patch.apply(asmApiVersion, className, classfileBuffer);
                    }
                }
            }
            return null;
        }
    }
}
