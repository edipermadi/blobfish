package com.github.edipermadi.security.blobfish;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Container Encoder Version 1
 *
 * @author Edi Permadi
 */
final class ContainerEncoderV1 implements ContainerEncoder {
    private static final String KEY_PROTECTION_ALGORITHM = "RSA/None/OAEPWithSHA256AndMGF1Padding";
    private static final String CIPHERING_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SIGNING_ALGORITHM = "SHA256withECDSA";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA256";

    private final X509Certificate signingCertificate;
    private final char[] password;
    private final List<X509Certificate> recipientCertificates;
    private final OutputStream outputStream;

    public ContainerEncoderV1(ContainerEncoderBuilder builder) {
        signingCertificate = builder.signingCertificate;
        password = builder.password;
        recipientCertificates = builder.recipientCertificates;
        outputStream = builder.outputStream;
    }

    @Override
    public ContainerEncoderV1 addBlob(final String path, final List<String> tags, final String mimeType, final InputStream inputStream){
        return this;
    }


    @Override
    public void close() throws IOException {

    }
}
