package com.github.edipermadi.security.blobfish;

import com.github.edipermadi.security.blobfish.codec.ContainerDecoder;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;
import com.google.common.base.Joiner;
import org.apache.commons.codec.digest.DigestUtils;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;

/**
 * Container Decoding Unit Test
 *
 * @author Edi Permadi
 */
public final class ContainerDecodingTest extends AbstractTest {
    private KeyStore keyStore;

    @BeforeClass
    @Parameters({"keystore-file-path", "keystore-file-password"})
    public void beforeClass(final String keystoreFilePath, final String keystoreFilePassword) throws KeyStoreException,
            IOException, CertificateException, NoSuchAlgorithmException {

        log("using keystore file path     : %s", keystoreFilePath);
        log("using keystore file password : %s", keystoreFilePassword);

        this.keyStore = KeyStore.getInstance("JKS");
        try (final FileInputStream fis = new FileInputStream(new File(keystoreFilePath))) {
            keyStore.load(fis, keystoreFilePassword.toCharArray());
        }
    }

    @BeforeMethod
    public void beforeMethod(final Method method) {
        Reporter.log("========================================", true);
        Reporter.log(method.getName(), true);
        Reporter.log("========================================", true);
    }

    @AfterMethod
    public void afterMethod() {
        Reporter.log("", true);
    }

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

    @Parameters({"blobfish-path"})
    @Test
    public void testGetBlobCount(final String blobfishPath) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final File containerFile = new File(blobfishPath);

        try (final FileInputStream containerFis = new FileInputStream(containerFile)) {

            final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                    .setInputStream(containerFis)
                    .build();
            final int count = containerDecoder.getBlobCount();
            Reporter.log("blob count : " + count, true);
        }
    }

    @Parameters({"blobfish-path"})
    @Test
    public void testGetCreationDate(final String blobfishPath) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final File containerFile = new File(blobfishPath);

        try (final FileInputStream containerFis = new FileInputStream(containerFile)) {

            final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                    .setInputStream(containerFis)
                    .build();
            final Date creationDate = containerDecoder.getCreationDate();
            Reporter.log("created at : " + creationDate, true);
        }
    }

    @Parameters({"blobfish-path"})
    @Test
    public void testGetSigningCertificate(final String blobfishPath) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final File containerFile = new File(blobfishPath);

        try (final FileInputStream containerFis = new FileInputStream(containerFile)) {

            final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                    .setInputStream(containerFis)
                    .build();
            final X509Certificate signingCertificate = containerDecoder.getSigningCertificate();
            Reporter.log("signing certificate subject : " + signingCertificate.getSubjectDN(), true);
        }
    }

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
    public void testDecodeBlobByPassword(final String blobfishPath,
                                         final String blobfishPassword,
                                         final String path1,
                                         final String path2,
                                         final String path3,
                                         final String path4,
                                         final String path5,
                                         final String path6,
                                         final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        Reporter.log("decrypting blob with password", true);
        for (int blobId = 0; blobId < plainPaths.size(); blobId++) {
            final File plainFile = new File(plainPaths.get(blobId));

            try (final FileInputStream containerFis = new FileInputStream(containerFile);
                 final FileInputStream plainFis = new FileInputStream(plainFile)) {

                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();
                final Blob blob = containerDecoder.getBlob(blobId, blobfishPassword);
                final Blob.Metadata metadata = blob.getMetadata();
                Reporter.log("  found blob:");
                Reporter.log(String.format("    path      = %s", metadata.getPath()), true);
                Reporter.log(String.format("    mime-type = %s", metadata.getMimeType()), true);
                Reporter.log(String.format("    tags = %s", Joiner.on(", ").join(metadata.getTags())), true);

                /* write to file */
                final File outputFile = new File(String.format("target/%s", new File(metadata.getPath()).getName()));
                Reporter.log("  writing to " + outputFile.getAbsolutePath(), true);
                try (final FileOutputStream fos = new FileOutputStream(outputFile)) {
                    fos.write(blob.getPayload());
                }

                final String reference = DigestUtils.sha256Hex(plainFis);
                final String actual = DigestUtils.sha256Hex(blob.getPayload());
                Assert.assertEquals(actual, reference);
            }
        }
    }

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
    public void testDecodeBlobByPasswordAndPath(final String blobfishPath,
                                                final String blobfishPassword,
                                                final String path1,
                                                final String path2,
                                                final String path3,
                                                final String path4,
                                                final String path5,
                                                final String path6,
                                                final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        Reporter.log("decrypting blob with password", true);
        for (final String plainPath : plainPaths) {
            final File plainFile = new File(plainPath);

            try (final FileInputStream containerFis = new FileInputStream(containerFile);
                 final FileInputStream plainFis = new FileInputStream(plainFile)) {

                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();
                final Blob blob = containerDecoder.getBlob(plainFile.getAbsolutePath(), blobfishPassword);
                final Blob.Metadata metadata = blob.getMetadata();
                Reporter.log("  found blob:");
                Reporter.log(String.format("    path      = %s", metadata.getPath()), true);
                Reporter.log(String.format("    mime-type = %s", metadata.getMimeType()), true);
                Reporter.log(String.format("    tags = %s", Joiner.on(", ").join(metadata.getTags())), true);

                /* write to file */
                final File outputFile = new File(String.format("target/%s", new File(metadata.getPath()).getName()));
                Reporter.log("  writing to " + outputFile.getAbsolutePath(), true);
                try (final FileOutputStream fos = new FileOutputStream(outputFile)) {
                    fos.write(blob.getPayload());
                }

                final String reference = DigestUtils.sha256Hex(plainFis);
                final String actual = DigestUtils.sha256Hex(blob.getPayload());
                Assert.assertEquals(actual, reference);
            }
        }
    }

    @Parameters({"blobfish-path",
            "keystore-entry-password",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "image1",
            "image2",
            "image3",
            "image4",
            "image5",
            "image6",
            "image7"})
    @Test
    public void testDecodeBlobByPrivateKey(final String blobfishPath,
                                           final String keyStoreEntryPassword,
                                           final String receiverAlias1,
                                           final String receiverAlias2,
                                           final String receiverAlias3,
                                           final String path1,
                                           final String path2,
                                           final String path3,
                                           final String path4,
                                           final String path5,
                                           final String path6,
                                           final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException, UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException {
        final List<String> aliases = Arrays.asList(receiverAlias1, receiverAlias2, receiverAlias3);
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        for (final String alias : aliases) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStoreEntryPassword.toCharArray());

            Reporter.log(String.format("decrypting blob with alias '%s'", alias), true);
            for (int blobId = 0; blobId < plainPaths.size(); blobId++) {
                final File plainFile = new File(plainPaths.get(blobId));

                try (final FileInputStream containerFis = new FileInputStream(containerFile);
                     final FileInputStream plainFis = new FileInputStream(plainFile)) {

                    final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                            .setInputStream(containerFis)
                            .build();

                    final Blob blob = containerDecoder.getBlob(blobId, certificate, privateKey);
                    final Blob.Metadata metadata = blob.getMetadata();

                    Reporter.log("  found blob:", true);
                    Reporter.log(String.format("    path      = %s", metadata.getPath()), true);
                    Reporter.log(String.format("    mime-type = %s", metadata.getMimeType()), true);
                    Reporter.log(String.format("    tags = %s", Joiner.on(", ").join(metadata.getTags())), true);

                    /* write to file */
                    final File outputFile = new File(String.format("target/%s", new File(metadata.getPath()).getName()));
                    Reporter.log("    writing to " + outputFile.getAbsolutePath(), true);
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

    @Parameters({"blobfish-path",
            "keystore-entry-password",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "image1",
            "image2",
            "image3",
            "image4",
            "image5",
            "image6",
            "image7"})
    @Test
    public void testDecodeBlobByPrivateKeyAndPath(final String blobfishPath,
                                                  final String keyStoreEntryPassword,
                                                  final String receiverAlias1,
                                                  final String receiverAlias2,
                                                  final String receiverAlias3,
                                                  final String path1,
                                                  final String path2,
                                                  final String path3,
                                                  final String path4,
                                                  final String path5,
                                                  final String path6,
                                                  final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException, UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException {
        final List<String> aliases = Arrays.asList(receiverAlias1, receiverAlias2, receiverAlias3);
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        for (final String alias : aliases) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStoreEntryPassword.toCharArray());

            Reporter.log(String.format("decrypting blob with alias '%s'", alias), true);
            for (final String plainPath : plainPaths) {
                final File plainFile = new File(plainPath);

                try (final FileInputStream containerFis = new FileInputStream(containerFile);
                     final FileInputStream plainFis = new FileInputStream(plainFile)) {

                    final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                            .setInputStream(containerFis)
                            .build();

                    final Blob blob = containerDecoder.getBlob(plainFile.getAbsolutePath(), certificate, privateKey);
                    final Blob.Metadata metadata = blob.getMetadata();

                    Reporter.log("  found blob:", true);
                    Reporter.log(String.format("    path      = %s", metadata.getPath()), true);
                    Reporter.log(String.format("    mime-type = %s", metadata.getMimeType()), true);
                    Reporter.log(String.format("    tags = %s", Joiner.on(", ").join(metadata.getTags())), true);

                    /* write to file */
                    final File outputFile = new File(String.format("target/%s", new File(metadata.getPath()).getName()));
                    Reporter.log("    writing to " + outputFile.getAbsolutePath(), true);
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
    public void testDecodeMetadataByPassword(final String blobfishPath,
                                             final String blobfishPassword,
                                             final String path1,
                                             final String path2,
                                             final String path3,
                                             final String path4,
                                             final String path5,
                                             final String path6,
                                             final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        Reporter.log("decrypting metadata with password", true);
        for (int blobId = 0; blobId < plainPaths.size(); blobId++) {
            try (final FileInputStream containerFis = new FileInputStream(containerFile)) {

                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();
                final Blob.Metadata metadata = containerDecoder.getMetadata(blobId, blobfishPassword);
                Reporter.log("  found metadata:");
                Reporter.log(String.format("    path      = %s", metadata.getPath()), true);
                Reporter.log(String.format("    mime-type = %s", metadata.getMimeType()), true);
                Reporter.log(String.format("    tags = %s", Joiner.on(", ").join(metadata.getTags())), true);
            }
        }
    }

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
    public void testDecodeMetadataByPasswordAndPath(final String blobfishPath,
                                                    final String blobfishPassword,
                                                    final String path1,
                                                    final String path2,
                                                    final String path3,
                                                    final String path4,
                                                    final String path5,
                                                    final String path6,
                                                    final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        Reporter.log("decrypting metadata with password", true);
        for (final String plainPath : plainPaths) {
            final File plainFile = new File(plainPath);

            try (final FileInputStream containerFis = new FileInputStream(containerFile)) {
                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();
                final Blob.Metadata metadata = containerDecoder.getMetadata(plainFile.getAbsolutePath(), blobfishPassword);
                Reporter.log("  found metadata:");
                Reporter.log(String.format("    path      = %s", metadata.getPath()), true);
                Reporter.log(String.format("    mime-type = %s", metadata.getMimeType()), true);
                Reporter.log(String.format("    tags = %s", Joiner.on(", ").join(metadata.getTags())), true);
            }
        }
    }

    @Parameters({"blobfish-path",
            "keystore-entry-password",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "image1",
            "image2",
            "image3",
            "image4",
            "image5",
            "image6",
            "image7"})
    @Test
    public void testDecodeMetadataByPrivateKey(final String blobfishPath,
                                               final String keyStoreEntryPassword,
                                               final String receiverAlias1,
                                               final String receiverAlias2,
                                               final String receiverAlias3,
                                               final String path1,
                                               final String path2,
                                               final String path3,
                                               final String path4,
                                               final String path5,
                                               final String path6,
                                               final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException, UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException {
        final List<String> aliases = Arrays.asList(receiverAlias1, receiverAlias2, receiverAlias3);
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        for (final String alias : aliases) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStoreEntryPassword.toCharArray());

            Reporter.log(String.format("decrypting metadata with alias '%s'", alias), true);
            for (int blobId = 0; blobId < plainPaths.size(); blobId++) {
                try (final FileInputStream containerFis = new FileInputStream(containerFile)) {

                    final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                            .setInputStream(containerFis)
                            .build();

                    final Blob.Metadata metadata = containerDecoder.getMetadata(blobId, certificate, privateKey);

                    Reporter.log("  found metadata:", true);
                    Reporter.log(String.format("    path      = %s", metadata.getPath()), true);
                    Reporter.log(String.format("    mime-type = %s", metadata.getMimeType()), true);
                    Reporter.log(String.format("    tags = %s", Joiner.on(", ").join(metadata.getTags())), true);
                }
            }
        }
    }

    @Parameters({"blobfish-path",
            "keystore-entry-password",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "image1",
            "image2",
            "image3",
            "image4",
            "image5",
            "image6",
            "image7"})
    @Test
    public void testDecodeMetadataByPrivateKeyAndPath(final String blobfishPath,
                                                      final String keyStoreEntryPassword,
                                                      final String receiverAlias1,
                                                      final String receiverAlias2,
                                                      final String receiverAlias3,
                                                      final String path1,
                                                      final String path2,
                                                      final String path3,
                                                      final String path4,
                                                      final String path5,
                                                      final String path6,
                                                      final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException, UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException {
        final List<String> aliases = Arrays.asList(receiverAlias1, receiverAlias2, receiverAlias3);
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        for (final String alias : aliases) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStoreEntryPassword.toCharArray());

            Reporter.log(String.format("decrypting metadata with alias '%s'", alias), true);
            for (final String plainPath : plainPaths) {
                final File plainFile = new File(plainPath);

                try (final FileInputStream containerFis = new FileInputStream(containerFile)) {

                    final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                            .setInputStream(containerFis)
                            .build();

                    final Blob.Metadata metadata = containerDecoder.getMetadata(plainFile.getAbsolutePath(), certificate, privateKey);

                    Reporter.log("  found blob:", true);
                    Reporter.log(String.format("    path      = %s", metadata.getPath()), true);
                    Reporter.log(String.format("    mime-type = %s", metadata.getMimeType()), true);
                    Reporter.log(String.format("    tags = %s", Joiner.on(", ").join(metadata.getTags())), true);
                }
            }
        }
    }

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
    public void testDecodePayloadByPassword(final String blobfishPath,
                                            final String blobfishPassword,
                                            final String path1,
                                            final String path2,
                                            final String path3,
                                            final String path4,
                                            final String path5,
                                            final String path6,
                                            final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        Reporter.log("decrypting payload with password", true);
        for (int blobId = 0; blobId < plainPaths.size(); blobId++) {
            final File plainFile = new File(plainPaths.get(blobId));

            try (final FileInputStream containerFis = new FileInputStream(containerFile);
                 final FileInputStream plainFis = new FileInputStream(plainFile)) {

                Reporter.log("  found payload:", true);
                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();
                final byte[] payload = containerDecoder.getPayload(blobId, blobfishPassword);

                final String reference = DigestUtils.sha256Hex(plainFis);
                final String actual = DigestUtils.sha256Hex(payload);
                Assert.assertEquals(actual, reference);
            }
        }
    }

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
    public void testDecodePayloadByPasswordAndPath(final String blobfishPath,
                                                   final String blobfishPassword,
                                                   final String path1,
                                                   final String path2,
                                                   final String path3,
                                                   final String path4,
                                                   final String path5,
                                                   final String path6,
                                                   final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        Reporter.log("decrypting payload with password", true);
        for (final String plainPath : plainPaths) {
            final File plainFile = new File(plainPath);

            try (final FileInputStream containerFis = new FileInputStream(containerFile);
                 final FileInputStream plainFis = new FileInputStream(plainFile)) {

                Reporter.log("  found payload:", true);
                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();
                final byte[] payload = containerDecoder.getPayload(plainFile.getAbsolutePath(), blobfishPassword);

                final String reference = DigestUtils.sha256Hex(plainFis);
                final String actual = DigestUtils.sha256Hex(payload);
                Assert.assertEquals(actual, reference);
            }
        }
    }

    @Parameters({"blobfish-path",
            "keystore-entry-password",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "image1",
            "image2",
            "image3",
            "image4",
            "image5",
            "image6",
            "image7"})
    @Test
    public void testDecodePayloadByPrivateKey(final String blobfishPath,
                                              final String keyStoreEntryPassword,
                                              final String receiverAlias1,
                                              final String receiverAlias2,
                                              final String receiverAlias3,
                                              final String path1,
                                              final String path2,
                                              final String path3,
                                              final String path4,
                                              final String path5,
                                              final String path6,
                                              final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException, UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException {
        final List<String> aliases = Arrays.asList(receiverAlias1, receiverAlias2, receiverAlias3);
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        for (final String alias : aliases) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStoreEntryPassword.toCharArray());

            Reporter.log(String.format("decrypting payload with alias '%s'", alias), true);
            for (int blobId = 0; blobId < plainPaths.size(); blobId++) {
                final File plainFile = new File(plainPaths.get(blobId));

                try (final FileInputStream containerFis = new FileInputStream(containerFile);
                     final FileInputStream plainFis = new FileInputStream(plainFile)) {

                    Reporter.log("  found payload:", true);
                    final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                            .setInputStream(containerFis)
                            .build();

                    final byte[] payload = containerDecoder.getPayload(blobId, certificate, privateKey);
                    final String reference = DigestUtils.sha256Hex(plainFis);
                    final String actual = DigestUtils.sha256Hex(payload);
                    Assert.assertEquals(actual, reference);
                }
            }
        }
    }

    @Parameters({"blobfish-path",
            "keystore-entry-password",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "image1",
            "image2",
            "image3",
            "image4",
            "image5",
            "image6",
            "image7"})
    @Test
    public void testDecodePayloadByPrivateKeyAndPath(final String blobfishPath,
                                                     final String keyStoreEntryPassword,
                                                     final String receiverAlias1,
                                                     final String receiverAlias2,
                                                     final String receiverAlias3,
                                                     final String path1,
                                                     final String path2,
                                                     final String path3,
                                                     final String path4,
                                                     final String path5,
                                                     final String path6,
                                                     final String path7) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException, UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException {
        final List<String> aliases = Arrays.asList(receiverAlias1, receiverAlias2, receiverAlias3);
        final List<String> plainPaths = Arrays.asList(path1, path2, path3, path4, path5, path6, path7);
        final File containerFile = new File(blobfishPath);

        for (final String alias : aliases) {
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStoreEntryPassword.toCharArray());

            Reporter.log(String.format("decrypting payload with alias '%s'", alias), true);
            for (final String plainPath : plainPaths) {
                final File plainFile = new File(plainPath);

                try (final FileInputStream containerFis = new FileInputStream(containerFile);
                     final FileInputStream plainFis = new FileInputStream(plainFile)) {

                    Reporter.log("  found payload:", true);
                    final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                            .setInputStream(containerFis)
                            .build();

                    final byte[] payload = containerDecoder.getPayload(plainFile.getAbsolutePath(), certificate, privateKey);
                    final String reference = DigestUtils.sha256Hex(plainFis);
                    final String actual = DigestUtils.sha256Hex(payload);
                    Assert.assertEquals(actual, reference);
                }
            }
        }
    }

    @Parameters({"blobfish-path",
            "blobfish-password"})
    @Test
    public void testGetTagsByPassword(final String blobfishPath,
                                      final String blobfishPassword) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final File containerFile = new File(blobfishPath);

        try (final FileInputStream containerFis = new FileInputStream(containerFile)) {
            Reporter.log("decrypting with password");
            final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                    .setInputStream(containerFis)
                    .build();
            final Set<String> tags = containerDecoder.getTags(blobfishPassword);
            Assert.assertNotNull(tags);
            Reporter.log(String.format("  found tags = %s", Joiner.on(", ").join(tags)), true);
        }
    }

    @Parameters({"blobfish-path",
            "keystore-entry-password",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2"})
    @Test
    public void testGetTagsByPrivateKey(final String blobfishPath,
                                        final String keyStoreEntryPassword,
                                        final String receiverAlias1,
                                        final String receiverAlias2,
                                        final String receiverAlias3) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException, KeyStoreException, UnrecoverableKeyException,
            NoSuchAlgorithmException {
        final File containerFile = new File(blobfishPath);
        final List<String> aliases = Arrays.asList(receiverAlias1, receiverAlias2, receiverAlias3);

        for (final String alias : aliases) {
            Reporter.log(String.format("decrypting with alias '%s'", alias), true);
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStoreEntryPassword.toCharArray());

            try (final FileInputStream containerFis = new FileInputStream(containerFile)) {

                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();

                final Set<String> tags = containerDecoder.getTags(certificate, privateKey);
                Assert.assertNotNull(tags);
                Reporter.log(String.format("  found tags = %s", Joiner.on(", ").join(tags)), true);
            }
        }
    }

    @Parameters({"blobfish-path",
            "blobfish-password"})
    @Test
    public void testListDirectoryByPassword(final String blobfishPath,
                                            final String blobfishPassword) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException {
        final File containerFile = new File(blobfishPath);

        Reporter.log("decrypting with password", true);
        try (final FileInputStream containerFis = new FileInputStream(containerFile)) {
            final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                    .setInputStream(containerFis)
                    .build();
            final Set<String> entries = containerDecoder.listDirectory("/", blobfishPassword);
            Assert.assertNotNull(entries);
            for (final String entry : entries) {
                if (entry.endsWith("/")) {
                    Reporter.log(String.format("  found directory : %s", entry), true);
                } else {
                    Reporter.log(String.format("  found blob      : %s", entry), true);
                }
            }
        }
    }

    @Parameters({"blobfish-path",
            "keystore-entry-password",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2"})
    @Test
    public void testListDirectoryByPrivateKey(final String blobfishPath,
                                              final String keyStoreEntryPassword,
                                              final String receiverAlias1,
                                              final String receiverAlias2,
                                              final String receiverAlias3) throws IOException, CertificateException,
            BlobfishDecodeException, BlobfishCryptoException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final File containerFile = new File(blobfishPath);
        final List<String> aliases = Arrays.asList(receiverAlias1, receiverAlias2, receiverAlias3);

        for (final String alias : aliases) {
            Reporter.log(String.format("decrypting with alias '%s'", alias), true);
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyStoreEntryPassword.toCharArray());

            try (final FileInputStream containerFis = new FileInputStream(containerFile)) {

                final ContainerDecoder containerDecoder = new ContainerDecoderBuilder()
                        .setInputStream(containerFis)
                        .build();

                final Set<String> entries = containerDecoder.listDirectory("/", certificate, privateKey);
                Assert.assertNotNull(entries);
                for (final String entry : entries) {
                    if (entry.endsWith("/")) {
                        Reporter.log(String.format("  found directory : %s", entry), true);
                    } else {
                        Reporter.log(String.format("  found blob      : %s", entry), true);
                    }
                }
            }
        }
    }
}
