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

package com.amazon.corretto.hotpatch.log4j2;

import com.amazon.corretto.hotpatch.HotPatch;
import com.amazon.corretto.hotpatch.Util;
import com.amazon.corretto.hotpatch.org.objectweb.asm.*;


public class Log4j2NoJndiLookup implements HotPatch {
    static final String CLASS_NAME = "org.apache.logging.log4j.core.lookup.JndiLookup";
    static final String CLASS_NAME_SLASH = CLASS_NAME.replace(".", "/");

    private final static String NAME = "Log4j2_NoJndiLookup";

    @Override
    public String getName() {
        return NAME;
    }

    public static boolean isEnabled(String args) {
        String param = "--disable-" + NAME;
        return args == null || !args.contains(param);
    }

    @Override
    public boolean isValidClass(String className) {
        return className.endsWith(CLASS_NAME)
                || className.endsWith(CLASS_NAME_SLASH);
    }

    @Override
    public byte[] apply(byte[] classfileBuffer) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new NoJndiLookupClassVisitor(cw);
        ClassReader cr = new ClassReader(classfileBuffer);
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    public static class NoJndiLookupClassVisitor extends ClassVisitor {
        public NoJndiLookupClassVisitor(ClassVisitor cv) {
            super(Util.asmApiVersion(), cv);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
            if ("lookup".equals(name)) {
                mv = new NoJndiLookupMethodVisitor(mv);
            }
            return mv;
        }
    }

    public static class NoJndiLookupMethodVisitor extends MethodVisitor implements Opcodes {

        public NoJndiLookupMethodVisitor(MethodVisitor mv) {
            super(Util.asmApiVersion(), mv);
        }

        @Override
        public void visitCode() {
            mv.visitCode();
            mv.visitLdcInsn("Patched JndiLookup::lookup()");
            mv.visitInsn(ARETURN);
        }
    }
}