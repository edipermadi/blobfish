package com.github.edipermadi.security.blobfish.codec;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Set;

/**
 * Container encoder interface
 *
 * @author Edi Permadi
 */
public interface ContainerEncoder {
    ContainerEncoderV1 addBlob(String path, Set<String> tags, String mimeType, InputStream inputStream) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, SignatureException;

    /**
     * Write blobs to output-stream given by {@link ContainerEncoderBuilder}
     *
     * @throws IOException when writing failed
     */
    void write() throws IOException;
}
