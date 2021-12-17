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

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;

import com.amazon.corretto.hotpatch.log4j2.Log4j2NoJndiLookup;

import static com.amazon.corretto.hotpatch.Logger.log;

public class HotPatchAgent {

  // version of this agent
  private static final int log4jFixerAgentVersion = 1;

  private static boolean agentLoaded = false;
  private static boolean staticAgent = false; // Set to true if loaded as a static agent from 'premain()'

  public static void premain(String args, Instrumentation inst) {
    staticAgent = true;
    agentmain(args, inst);
  }

  private static List<HotPatch> loadPatches(String args) {
    List<HotPatch> patches = new ArrayList<>();
    if (Log4j2NoJndiLookup.isEnabled(args)) {
      patches.add(new Log4j2NoJndiLookup());
    }
    return patches;
  }

  public static void agentmain(String args, Instrumentation inst) {
    if (agentLoaded) {
      log("Info: hot patch agent already loaded");
      return;
    }

    Logger.setVerbose(staticAgent, args);
    final int api = Util.asmApiVersion();
    log("Loading Java Agent version " + log4jFixerAgentVersion + " (using ASM" + (api >> 16) + ").");

    final List<HotPatch> patches = loadPatches(args);
    ClassFileTransformer transformer = new ClassFileTransformer() {
      @Override
      public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
        if (className != null) {
          for (HotPatch patch : patches) {
            if (patch.isValidClass(className)) {
              Logger.log("Transforming + " + className + " (" + loader + ") with patch " + patch.getName());
              return patch.apply(classfileBuffer);
            }
          }
        }
        return null;
      }
    };

    if (staticAgent) {
      inst.addTransformer(transformer);
    } else {
      int patchesApplied = 0;

      inst.addTransformer(transformer, true);
      List<Class<?>> classesToRetransform = new ArrayList<>();
      for (Class<?> c : inst.getAllLoadedClasses()) {
        String className = c.getName();
        for (HotPatch patch : patches) {
          if (patch.isValidClass(className)) {
            log("Patching + " + className + " (" + c.getClassLoader() + ") with patch " + patch.getName());
            classesToRetransform.add(c);
            ++patchesApplied;
          }
        }
      }
      if (classesToRetransform.size() > 0) {
        try {
          inst.retransformClasses(classesToRetransform.toArray(new Class[0]));
        } catch (UnmodifiableClassException uce) {
          log(String.valueOf(uce));
        }
      }

      if (patchesApplied == 0) {
        log("Vulnerable classes were not found. This agent will continue to run " +
            "and transform the vulnerable class if it is loaded. Note that if you have shaded " +
            "or otherwise changed the package name for log4j classes, then this tool may not " +
            "find them.");
      }
    }

    agentLoaded = true;

    // set the version of this agent in a system property so that
    // subsequent clients can read it and skip re-patching.
    try {
      System.setProperty(Constants.LOG4J_FIXER_AGENT_VERSION, String.valueOf(log4jFixerAgentVersion));
    } catch (Exception e) {
      log("Warning: Could not record agent version in system property: " + e.getMessage());
      log("Warning: This will make it more difficult to test if agent is already loaded, but will not prevent patching");
    }
  }
}
