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

import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

import com.amazon.corretto.hotpatch.interfaces.Logger;

/**
 * A very simple logger that does not really care about the logger levels, but it can be turned off completely when not
 * in verbose mode.
 */
public class LoggerImpl implements com.amazon.corretto.hotpatch.interfaces.Logger {
    private static final PrintStream out = System.err;
    public static final String VERBOSE_PROPERTY_NAME = "log4jFixerVerbose";
    private static final Map<Integer, String> LEVELS_TO_STRING = new HashMap<>();
    static {
        LEVELS_TO_STRING.put(Logger.TRACE, "Trace");
        LEVELS_TO_STRING.put(Logger.DEBUG, "Debug");
        LEVELS_TO_STRING.put(Logger.INFO, "Info");
        LEVELS_TO_STRING.put(Logger.WARN, "Warn");
        LEVELS_TO_STRING.put(Logger.ERROR, "Error");
    }

    private static boolean verbose = true;

    public LoggerImpl() {
    }

    public LoggerImpl(String[] args) {
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

    @Override
    public void log(final String message) {
        if (verbose) {
            out.println(message);
        }
    }

    @Override
    public void log(final Exception ex) {
        if (verbose) {
            ex.printStackTrace(out);
        }
    }

    @Override
    public void log(String message, Exception ex) {
        log(message);
        log(ex);
    }

    @Override
    public void log(int logLevel, String message) {
        log(LEVELS_TO_STRING.get(logLevel) + ":" + message);
    }

    @Override
    public void log(int logLevel, String message, Exception ex) {
        log(logLevel, message);
        log(logLevel, ex);
    }

    @Override
    public void log(int logLevel, Exception ex) {
        log(ex);
    }

    public void setVerbose(String args) {
        // First, check for a system property
        try {
            String propertyValue = System.getProperty(VERBOSE_PROPERTY_NAME);
            if (propertyValue != null) {
                verbose = Boolean.parseBoolean(propertyValue);
            }
        } catch (Exception e) {
            // nothing to do here, ensure we don't fail due to SecurityManager or wrong value for the property
        }

        // If log4jFixerVerbose is present in the agent arguments, pick that value.
        if (args != null && args.contains(VERBOSE_PROPERTY_NAME)) {
            verbose = !args.contains(VERBOSE_PROPERTY_NAME + "=false");
        }
    }

    public String getAgentLogArg() {
        return VERBOSE_PROPERTY_NAME + "=" + verbose;
    }
}
