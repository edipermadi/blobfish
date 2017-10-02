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
     * @return metadata object, see {@link Metadata}
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
        /**
         * Get blob path
         *
         * @return string of blob path
         */
        String getPath();

        /**
         * Get blob tags
         *
         * @return set of blob tags (in lower case)
         */
        Set<String> getTags();

        /**
         * Blob mime-type hint
         *
         * @return string of mime-type detected while encoding
         */
        String getMimeType();
    }
}
