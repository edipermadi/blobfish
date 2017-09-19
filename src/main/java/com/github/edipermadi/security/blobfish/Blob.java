package com.github.edipermadi.security.blobfish;

import java.util.Set;

/**
 * Blob entry data type interface
 *
 * @author Edi Permadi
 */
public interface Blob {
    /**
     * Get blob metadata
     *
     * @return
     */
    Metadata getMetadata();

    /**
     * Get blob payload
     *
     * @return byte array of plain blob
     */
    byte[] getPayload();

    /**
     * Blob metadata data type interface
     *
     * @author Edi Permadi
     */
    interface Metadata {
        String getPath();

        Set<String> getTags();

        String getMimeType();
    }
}
