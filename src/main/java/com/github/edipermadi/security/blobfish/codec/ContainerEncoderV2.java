package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishEncodeException;

/**
 * Blobfish container encoder version 2 (supports payload compression GZIP)
 *
 * @author Edi Permadi
 */
final class ContainerEncoderV2 extends ContainerEncoderV1 {

    /**
     * Container Encoder Version 2 Constructor
     *
     * @param builder Container Encoder Builder Instance
     * @throws BlobfishCryptoException when cryptographic exception occurred
     * @throws BlobfishEncodeException whn encoding exception occurred
     */
    ContainerEncoderV2(ContainerEncoderBuilder builder) throws BlobfishCryptoException, BlobfishEncodeException {
        super(builder, 2, true);
    }
}
