package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishEncodeException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

/**
 * Container encoder interface
 *
 * @author Edi Permadi
 */
public interface ContainerEncoder {
    /**
     * Add blob entry
     *
     * @param path        path of blob
     * @param tags        tags of blob
     * @param mimeType    mime type of plain blob
     * @param inputStream input stream of plain blob
     * @return this object
     * @throws BlobfishEncodeException when encoding failed
     * @throws BlobfishCryptoException when encryption failed
     * @throws IOException when reading plain blob failed
     */
    ContainerEncoder addBlob(String path, Set<String> tags, String mimeType, InputStream inputStream) throws BlobfishEncodeException, BlobfishCryptoException, IOException;

    /**
     * Write blobs to output-stream given by {@link ContainerEncoderBuilder}
     *
     * @throws IOException when writing failed
     */
    void write() throws IOException;
}
