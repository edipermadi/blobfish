package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;

/**
 * Blob Abstract Data Type implementation
 *
 * @author Edi Permadi
 */
final class BlobImpl implements Blob {
    private final MetadataImpl metadata;
    private final byte[] payload;

    /**
     * Class constructor
     *
     * @param metadata blob metadata entry
     * @param payload  blob payload entry
     */
    BlobImpl(final BlobfishProto.Blobfish.Body.Metadata metadata, final BlobfishProto.Blobfish.Body.Payload payload) {
        if (metadata == null) {
            throw new IllegalArgumentException("metadata is null");
        } else if (payload == null) {
            throw new IllegalArgumentException("payload is null");
        }

        this.metadata = new MetadataImpl(metadata);
        this.payload = payload.getData().toByteArray();
    }

    @Override
    public Metadata getMetadata() {
        return metadata;
    }

    @Override
    public byte[] getPayload() {
        return payload;
    }
}
