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

    public ContainerDecoderBuilder setInputStream(final InputStream inputStream) {
        if (inputStream == null) {
            throw new IllegalArgumentException("input stream is null");
        }
        this.inputStream = inputStream;
        return this;
    }

    public ContainerDecoder build() throws IOException, CertificateException {
        if (inputStream == null) {
            throw new IllegalStateException("input stream is required");
        }

        final BlobfishProto.Blobfish blobFish = BlobfishProto.Blobfish.parseDelimitedFrom(inputStream);
        if (blobFish.getMagic() != Const.MAGIC_CODE) {
            throw new IllegalStateException("unexpected magic code");
        }

        switch (blobFish.getVersion()){
            case 1:
                return new ContainerDecoderV1(blobFish);
            default:
                throw new IllegalStateException("unsupported container version");
        }
    }
}
