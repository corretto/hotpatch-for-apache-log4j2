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

/**
 * A logger that can be used by the different {@link Patcher}. The different patchers should not create their own
 * loggers but use the logger received from the Agent that adheres to this interface.
 */
public interface Logger {
    // Different levels
    int ERROR = 100;
    int WARN = 200;
    int INFO = 300;
    int DEBUG = 400;
    int TRACE = 500;

    /**
     * Log a message to the logger without specifying a level.
     * @param message The message to log.
     */
    void log(String message);

    /**
     * Log an exception to the logger without specifying a level.
     * @param ex Exception to log
     */
    void log(Exception ex);

    /**
     * Log a message with an exception to the logger without specifying a level.
     * @param message The message to log.
     * @param ex Exception to log
     */
    void log(String message, Exception ex);

    /**
     * Log a message with the specified level.
     * @param logLevel level for the message
     * @param message The message to log.
     */
    void log(int logLevel, String message);

    /**
     * Log an exception with the specified level.
     * @param logLevel level for the message
     * @param ex Exception to log
     */
    void log(int logLevel, Exception ex);

    /**
     * Log a message with an exception and the specified level.
     * @param logLevel level for the message
     * @param message The message to log.
     * @param ex Exception to log
     */
    void log(int logLevel, String message, Exception ex);
}
