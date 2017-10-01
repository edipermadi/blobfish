package com.github.edipermadi.security.blobfish;

import com.github.edipermadi.security.blobfish.codec.ContainerDecoder;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
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
    public void testDecode(final String blobfishPath, final String blobfishPassword) throws IOException, CertificateException, BlobfishDecodeException, BlobfishCryptoException {
        final File file = new File(blobfishPath);
        try (final FileInputStream fis = new FileInputStream(file)) {
            final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                    .setInputStream(fis)
                    .build();
            containerDecoder.getBlob(0,blobfishPassword);
        }
    }

}
