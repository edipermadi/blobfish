package com.github.edipermadi.security.blobfish;

import java.io.Closeable;
import java.io.InputStream;
import java.util.List;

/**
 * Container encoder interface
 *
 * @author Edi Permadi
 */
public interface ContainerEncoder extends Closeable {
    ContainerEncoderV1 addBlob(String path, List<String> tags, String mimeType, InputStream inputStream);
}
