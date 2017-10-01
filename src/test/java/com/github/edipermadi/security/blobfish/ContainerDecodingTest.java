package com.github.edipermadi.security.blobfish;

import com.github.edipermadi.security.blobfish.codec.ContainerDecoder;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;
import com.google.common.base.Joiner;
import org.apache.commons.codec.digest.DigestUtils;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

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

    @Parameters({"blobfish-path",
            "blobfish-password",
            "image1",
            "image2",
            "image3",
            "image4",
            "image5",
            "image6",
            "image7"})
    @Test
    public void testDecodeByPassword(final String blobfishPath,
                                     final String blobfishPassword,
                                     final String path1,
                                     final String path2,
                                     final String path3,
                                     final String path4,
                                     final String path5,
                                     final String path6,
                                     final String path7) throws IOException, CertificateException, BlobfishDecodeException, BlobfishCryptoException {
        Reporter.log("testDecodeByPassword", true);
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        for (int blobId = 0; blobId < plainPaths.size(); blobId++) {
            final File plainFile = new File(plainPaths.get(blobId));

            try (final FileInputStream containerFis = new FileInputStream(containerFile);
                 final FileInputStream plainFis = new FileInputStream(plainFile)) {

                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();
                final Blob blob = containerDecoder.getBlob(blobId, blobfishPassword);
                final Blob.Metadata metadata = blob.getMetadata();
                Reporter.log(String.format("path      = %s", metadata.getPath()), true);
                Reporter.log(String.format("mime-type = %s", metadata.getMimeType()), true);
                Reporter.log(String.format("tags = %s", Joiner.on(", ").join(metadata.getTags())), true);

                /* write to file */
                final File outputFile = new File(String.format("target/%s", new File(metadata.getPath()).getName()));
                Reporter.log("writing to " + outputFile.getAbsolutePath(), true);
                try (final FileOutputStream fos = new FileOutputStream(outputFile)) {
                    fos.write(blob.getPayload());
                }

                final String reference = DigestUtils.sha256Hex(plainFis);
                final String actual = DigestUtils.sha256Hex(blob.getPayload());
                Assert.assertEquals(actual, reference);
            }
        }
    }
}