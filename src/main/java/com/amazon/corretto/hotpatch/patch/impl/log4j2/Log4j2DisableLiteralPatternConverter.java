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

package com.amazon.corretto.hotpatch.patch.impl.log4j2;

import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassReader;
import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassVisitor;
import com.amazon.corretto.hotpatch.org.objectweb.asm.ClassWriter;
import com.amazon.corretto.hotpatch.org.objectweb.asm.Label;
import com.amazon.corretto.hotpatch.org.objectweb.asm.MethodVisitor;
import com.amazon.corretto.hotpatch.org.objectweb.asm.Opcodes;
import com.amazon.corretto.hotpatch.patch.ClassTransformerHotPatch;

public class Log4j2DisableLiteralPatternConverter implements ClassTransformerHotPatch {
    static final String CLASS_NAME = "org.apache.logging.log4j.core.pattern.LiteralPatternConverter";
    static final String CLASS_NAME_SLASH = CLASS_NAME.replace(".", "/");

    private final static String NAME = "Log4j2_DisableLiteralPatternConverter";

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return "Fixes CVE-2021-45105 by patching the LiteralPatternConverter to disable lookup in message patterns.";
    }

    @Override
    public boolean isTargetClass(String className) {
        return className.endsWith(CLASS_NAME) || className.endsWith(CLASS_NAME_SLASH);
    }

    public static boolean isEnabled(String args) {
        String param = "--enable-" + NAME;
        return args != null && args.contains(param);
    }

    @Override
    public byte[] apply(int asmApiVersion, String className, byte[] classfileBuffer) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new DisableLiteralPatternConverterClassVisitor(asmApiVersion, cw);
        ClassReader cr = new ClassReader(classfileBuffer);
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    public static class DisableLiteralPatternConverterClassVisitor extends ClassVisitor {

        public DisableLiteralPatternConverterClassVisitor(int asmApiVersion, ClassVisitor classVisitor) {
            super(asmApiVersion, classVisitor);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String signature, String[] exceptions) {
            MethodVisitor mv = cv.visitMethod(access, name, desc, signature, exceptions);
            if ("format".equals(name)) {
                mv = new LiteralPatternConverterMethodVisitor(api, mv);
            }
            return mv;
        }
    }

    public static class LiteralPatternConverterMethodVisitor extends MethodVisitor implements Opcodes {
        private static final String OWNER = CLASS_NAME_SLASH;
        private static final String DESC = "Z";
        private static final String NAME = "substitute";
        enum State {
            CLEAR,
            LOADED_SUBSTITUTE,
        }

        private State state = State.CLEAR;

        public LiteralPatternConverterMethodVisitor(int asmApiVersion, MethodVisitor methodVisitor) {
            super(asmApiVersion, methodVisitor);
        }

        @Override
        public void visitFieldInsn(int opc, String owner, String name, String desc) {
            if (OWNER.equals(owner) && NAME.equals(name) && DESC.equals(desc) && opc == GETFIELD) {
                visitState();
            } else {
                clearState();
            }
            mv.visitFieldInsn(opc, owner, name, desc);
        }

        @Override
        public void visitJumpInsn(int opc, Label label) {
            mv.visitJumpInsn(opc, label);
            if (state == State.LOADED_SUBSTITUTE && opc == IFEQ) {
                mv.visitJumpInsn(GOTO, label);
            }
            clearState();

        }

        private void clearState() {
            state = State.CLEAR;
        }

        private void visitState() {
            state = State.LOADED_SUBSTITUTE;
        }

        @Override
        public void visitVarInsn(int opcode, int var) {
            clearState();
            mv.visitVarInsn(opcode, var);
        }

        @Override
        public void visitTypeInsn(int opcode, String desc) {
            clearState();
            mv.visitTypeInsn(opcode, desc);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String desc) {
            clearState();
            mv.visitMethodInsn(opcode, owner, name, desc);
        }

        @Override
        public void visitLabel(Label label) {
            mv.visitLabel(label);
        }

        @Override
        public void visitLdcInsn(Object cst) {
            clearState();
            mv.visitLdcInsn(cst);
        }

        @Override
        public void visitIincInsn(int var, int increment) {
            clearState();
            mv.visitIincInsn(var, increment);
        }

        @Override
        public void visitTableSwitchInsn(int min, int max, Label dflt, Label[] labels) {
            mv.visitTableSwitchInsn(min, max, dflt, labels);
        }

        @Override
        public void visitLookupSwitchInsn(Label dflt, int[] keys, Label[] labels) {
            mv.visitLookupSwitchInsn(dflt, keys, labels);
        }

        @Override
        public void visitMultiANewArrayInsn(String desc, int dims) {
            mv.visitMultiANewArrayInsn(desc, dims);
        }

        @Override
        public void visitTryCatchBlock(Label start, Label end, Label handler, String type) {
            mv.visitTryCatchBlock(start, end, handler, type);
        }

        @Override
        public void visitLocalVariable(String name, String desc, String signature, Label start, Label end, int index) {
            mv.visitLocalVariable(name, desc, signature, start, end, index);
        }

        @Override
        public void visitLineNumber(int line, Label start) {
            mv.visitLineNumber(line, start);
        }
    }
}
