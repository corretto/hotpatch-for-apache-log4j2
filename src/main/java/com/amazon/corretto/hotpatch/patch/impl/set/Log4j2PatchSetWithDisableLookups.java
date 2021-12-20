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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.amazon.corretto.hotpatch.patch.ClassTransformerHotPatch;
import com.amazon.corretto.hotpatch.patch.impl.log4j2.Log4j2DisableLiteralPatternConverter;
import com.amazon.corretto.hotpatch.patch.impl.log4j2.Log4j2NoJndiLookup;

/**
 * Patch set contains the following patches
 * {@link Log4j2NoJndiLookup}
 * {@link Log4j2DisableLiteralPatternConverter}
 */
public class Log4j2PatchSetWithDisableLookups extends PatchSetPatcher {
    private final List<ClassTransformerHotPatch> patches = Collections.unmodifiableList(Arrays.asList(
            (ClassTransformerHotPatch) new Log4j2NoJndiLookup(),
            (ClassTransformerHotPatch) new Log4j2DisableLiteralPatternConverter()
    ));

    @Override
    public List<ClassTransformerHotPatch> getPatches() {
        return patches;
    }

    @Override
    public String getName() {
        return "log4j2";
    }

    @Override
    public int getVersion() {
        return 2;
    }

    @Override
    public String getShortDescription() {
        return "Fix vulnerabilities in Log4j2 related to message lookups and recursive lookups";
    }
}
