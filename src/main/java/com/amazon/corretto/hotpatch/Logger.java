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

import java.security.AccessControlException;

public class Logger {
    public static final String VERBOSE_PROPERTY_NAME = "log4jFixerVerbose";
    private static boolean verbose = true;

    public static void log(final String message) {
        if (verbose) {
            System.out.println(message);
        }
    }

    public static void log(final Exception ex) {
        if (verbose) {
            ex.printStackTrace(System.out);
        }
    }

    public static void setVerbose(boolean staticAgent, String args) {
        // First, if we are running as a static agent, check for a system property
        if (staticAgent) {
            try {
                String propertyValue = System.getProperty(VERBOSE_PROPERTY_NAME);
                if (propertyValue != null) {
                    verbose = Boolean.parseBoolean(propertyValue);
                }
            } catch (Exception e) {
                // nothing to do here, ensure we don't fail due to SecurityManager or wrong value for the property
            }
        }

        // If log4jFixerVerbose is present in the agent arguments, pick that value.
        if (args != null && args.contains(VERBOSE_PROPERTY_NAME)) {
            verbose = !args.contains(VERBOSE_PROPERTY_NAME + "=false");
        }
    }

    /**
     * Determine if we should operate in verbose mode be in verbose mode when running the jar to patch. Default mode is
     * verbose, but it can be disabled with a command line argument or a system property.
     * @param args Java application args
     */
    public static void setVerbose(String[] args) {
        for (String arg : args) {
            if (arg.equals("-q") || arg.equals("--quiet")) {
                verbose = false;
                return;
            }
        }
        try {
            verbose = Boolean.parseBoolean(System.getProperty(VERBOSE_PROPERTY_NAME, "true"));
        } catch (Exception ace) {
            // nothing to do here, ensure we don't fail due to SecurityManager
        }
    }

    public static String getAgentLogArg() {
        return " " + VERBOSE_PROPERTY_NAME + "=" + verbose;
    }
}
