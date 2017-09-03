package com.github.edipermadi.security.blobfish;

import javax.crypto.NoSuchPaddingException;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.List;

/**
 * Container encoder interface
 *
 * @author Edi Permadi
 */
public interface ContainerEncoder extends Closeable {
    ContainerEncoderV1 addBlob(String path, List<String> tags, String mimeType, InputStream inputStream) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, SignatureException;
}
