package com.github.edipermadi.security.blobfish.codec;

/**
 * Container base implementation
 *
 * @author Edi Permadi
 */
abstract class Const {
    static final long MAGIC_CODE = 0x75676c7966697368L;
    static final int VERSION_NUMBER = 1;
    static final int ITERATION_NUMBER = 65536;
    static final int KEY_LENGTH_BITS = 128;
}
