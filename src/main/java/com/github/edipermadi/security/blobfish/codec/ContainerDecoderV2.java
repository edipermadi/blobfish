package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.generated.BlobfishProto;

import java.io.IOException;
import java.security.cert.CertificateException;

/**
 * Container Decoder Version 2, Inherits Version 1 implementation with compression enabled
 *
 * @author Edi Permadi
 */
final class ContainerDecoderV2 extends ContainerDecoderV1 {
    /**
     * Class constructor
     *
     * @param blobFish blobfish object
     */
    ContainerDecoderV2(final BlobfishProto.Blobfish blobFish) throws IOException, CertificateException {
        super(blobFish, true);
    }
}
