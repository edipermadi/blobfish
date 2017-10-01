package com.github.edipermadi.security.blobfish;

import com.github.edipermadi.security.blobfish.codec.ContainerDecoder;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;
import com.google.common.base.Joiner;
import org.testng.Reporter;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;

/**
 * Container Decoding Unit Test
 *
 * @author Edi Permadi
 */
public final class ContainerDecodingTest extends AbstractTest {
    //------------------------------------------------------------------------------------------------------------------
    // Negative Test Cases
    //------------------------------------------------------------------------------------------------------------------
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNulInputStreamIsGivenThenExceptionIsThrown() {
        final ContainerDecoderBuilder builder = new ContainerDecoderBuilder();
        builder.setInputStream(null);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void whenInputStreamNotSetThenExceptionIsThrown() throws IOException, CertificateException {
        final ContainerDecoderBuilder builder = new ContainerDecoderBuilder();
        builder.build();
    }

    //------------------------------------------------------------------------------------------------------------------
    // Positive Test Cases
    //------------------------------------------------------------------------------------------------------------------

    @Parameters({"blobfish-path", "blobfish-password"})
    @Test
    public void testDecodeByPassword(final String blobfishPath, final String blobfishPassword) throws IOException, CertificateException, BlobfishDecodeException, BlobfishCryptoException {
        final File file = new File(blobfishPath);
        try (final FileInputStream fis = new FileInputStream(file)) {
            final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                    .setInputStream(fis)
                    .build();
            final Blob blob = containerDecoder.getBlob(0, blobfishPassword);
            final Blob.Metadata metadata = blob.getMetadata();
            Reporter.log(String.format("path      = %s", metadata.getPath()), true);
            Reporter.log(String.format("mime-type = %s", metadata.getMimeType()), true);
            Reporter.log(String.format("tags = %s", Joiner.on(", ").join(metadata.getTags(), ", ")), true);
        }
    }

}
