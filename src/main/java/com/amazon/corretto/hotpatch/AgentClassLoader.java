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

import java.net.URL;
import java.net.URLClassLoader;

public class AgentClassLoader extends URLClassLoader {
    private static final String INTERFACE_PACKAGE = "com.amazon.corretto.hotpatch.interfaces";
    public AgentClassLoader(URL[] urls) {
        super(urls);
    }
    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        // We revert the default search order and try to load everything from the agent jar file
        // to override corresponding classes which had already been loaded during a previous attach
        // of the agent.
        // The only exception to this rule are the common interfaces (i.e. "Patcher" and "Logger"). These interfaces
        // are used by the agent and are loaded in its ClassLoader. The exception is done for all the classes in the
        // INTERFACE_PACKAGE, so if more interfaces are added, they need to be put there.
        if (!name.startsWith(INTERFACE_PACKAGE)) {
            Class<?> c = findClass(name);
            if (c != null) {
                if (resolve) {
                    resolveClass(c);
                }
                return c;
            }
        }
        return super.loadClass(name, resolve);
    }

    @Override
    protected Class<?> findClass(String name) {
        // Return null instead of throwing to simplify the code
        Class<?> c;
        try {
            c = super.findClass(name);
        } catch (ClassNotFoundException cnfe) {
            c = null;
        }
        return c;
    }
}