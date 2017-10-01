package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.generated.BlobfishProto;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;

/**
 * Container decoder builder.
 * This class creates an instance of blobfish decoder based on given parameter
 *
 * @author Edi Permadi
 */
public final class ContainerDecoderBuilder {
    private InputStream inputStream;

    /**
     * Set decoder input stream
     *
     * @param inputStream container input stream
     * @return this instance
     */
    public ContainerDecoderBuilder setInputStream(final InputStream inputStream) {
        if (inputStream == null) {
            throw new IllegalArgumentException("input stream is null");
        }
        this.inputStream = inputStream;
        return this;
    }

    /**
     * Build container decoder
     *
     * @return container decoder object
     * @throws IOException          when container reading failed
     * @throws CertificateException when sender certificate cannot be retrieved from container
     */
    public ContainerDecoder build() throws IOException, CertificateException {
        if (inputStream == null) {
            throw new IllegalStateException("input stream is required");
        }

        final BlobfishProto.Blobfish blobFish = BlobfishProto.Blobfish.parseDelimitedFrom(inputStream);
        if (blobFish.getMagic() != Const.MAGIC_CODE) {
            throw new IllegalStateException("unexpected magic code");
        }

        switch (blobFish.getVersion()) {
            case 1:
                return new ContainerDecoderV1(blobFish);
            default:
                throw new IllegalStateException("unsupported container version");
        }
    }
}
