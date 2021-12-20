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

import java.util.Collections;
import java.util.List;

import com.amazon.corretto.hotpatch.patch.ClassTransformerHotPatch;

public class Log4j2PatchSetV0 extends PatchSetPatcher {
    private final List<ClassTransformerHotPatch> patches = Collections.emptyList();

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
        return 0;
    }

    @Override
    public String getShortDescription() {
        return "Apply no patches related to Log4j2";
    }
}
