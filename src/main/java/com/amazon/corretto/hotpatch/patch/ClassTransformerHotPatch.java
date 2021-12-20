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

package com.amazon.corretto.hotpatch.patch;

/**
 * A ClassTransformerHotPatch represents a transformation to one or more classes. Each instance should fix one and only
 * one problem. Multiple instances of this interface can be bundled together in a
 * {@link com.amazon.corretto.hotpatch.patch.impl.set.PatchSetPatcher} to fix multiple problems that are related and
 * treated together, for example, multiple vulnerabilities in the same library.
 */
public interface ClassTransformerHotPatch {
    /**
     * Name of the HotPatch that will be applied
     * @return Name of the HotPatch that will be applied
     */
    String getName();

    /**
     * A description of what this patch does.
     * @return String with the description of what this patch does.
     */
    String getDescription();

    /**
     * A check to validate if this patch intends to modify the specific class.
     * @param className Name of the class. The patch should accept the class name using either dots (.) or slashes (/)
     *                  as separators.
     * @return True if the patch modifies the specified class.
     */
    boolean isTargetClass(String className);

    /**
     * Apply the patch to the selected class.
     * @param asmApiVersion Version of the ASM api to use.
     * @param className Name of the class we are applying the patch to. This will match a value previously accepted in
     *                  {@link #isTargetClass(String)}
     * @param classfileBuffer the JVMS ClassFile structure of the class to be patched
     * @return the binary content of the patched JVMS ClassFile structure
     */
    byte[] apply(int asmApiVersion, String className, byte[] classfileBuffer);
}
