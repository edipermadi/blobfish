package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;

import java.util.HashSet;
import java.util.Set;

/**
 * Metadata Abstract Data Type implementation
 *
 * @author Edi Permadi
 */
final class MetadataImpl implements Blob.Metadata {
    private final BlobfishProto.Blobfish.Body.Metadata metadata;

    /**
     * Class constructor
     *
     * @param metadata metadata entry from decoded proto file
     */
    MetadataImpl(final BlobfishProto.Blobfish.Body.Metadata metadata) {
        if (metadata == null) {
            throw new IllegalArgumentException("metadata entry is null");
        }
        this.metadata = metadata;
    }

    @Override
    public String getPath() {
        return metadata.getPath();
    }

    @Override
    public Set<String> getTags() {
        /* extract tags */
        final Set<String> tags = new HashSet<>();
        for (int i = 0; i < metadata.getTagsCount(); i++) {
            tags.add(metadata.getTags(i));
        }
        return tags;
    }

    @Override
    public String getMimeType() {
        return metadata.getMimeType();
    }
}
