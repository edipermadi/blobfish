package com.github.edipermadi.security.blobfish;

import com.github.edipermadi.security.blobfish.codec.ContainerEncoder;
import com.github.edipermadi.security.blobfish.codec.ContainerEncoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishEncodeException;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.tika.config.TikaConfig;
import org.apache.tika.exception.TikaException;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.mime.MediaType;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Set;

/**
 * Container Encoder Builder Unit Test
 *
 * @author Edi Permadi
 */
public final class ContainerEncodingTest extends AbstractTest {
    private KeyStore keyStore;
    private TikaConfig tika;

    @BeforeClass
    @Parameters({"keystore-file-path", "keystore-file-password"})
    public void beforeClass(final String keystoreFilePath, final String keystoreFilePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, TikaException {
        this.tika = new TikaConfig();

        log("using keystore file path     : %s", keystoreFilePath);
        log("using keystore file password : %s", keystoreFilePassword);

        this.keyStore = KeyStore.getInstance("JKS");
        try (final FileInputStream fis = new FileInputStream(new File(keystoreFilePath))) {
            keyStore.load(fis, keystoreFilePassword.toCharArray());
        }
    }

    //------------------------------------------------------------------------------------------------------------------
    // Negative Test Cases
    //------------------------------------------------------------------------------------------------------------------
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNegativeVersionIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setVersion(-1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenZeroVersionIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setVersion(0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullSigningCertificateIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setSigningCertificate(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    @Parameters({"keystore-alias-enc-sender"})
    public void whenRsaSigningCertificateIsGivenThenExceptionThrown(final String alias) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        new ContainerEncoderBuilder()
                .setSigningCertificate(certificate);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    @Parameters({"keystore-alias-enc-sender", "keystore-entry-password"})
    public void whenRsaSigningPrivateKeyIsGivenThenExceptionThrown(final String alias, final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        new ContainerEncoderBuilder()
                .setSigningKey(privateKey);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullEncryptionCertificateIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .addRecipientCertificate(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    @Parameters({"keystore-alias-sig-sender"})
    public void whenEcEncryptionCertificateIsGivenThenExceptionThrown(final String alias) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        new ContainerEncoderBuilder()
                .addRecipientCertificate(certificate);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullPasswordIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setPassword(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenEmptyPasswordIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setPassword("");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenWhitespacePasswordIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setPassword("    ");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullOutputStreamIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setOutputStream(null);
    }

    @Parameters({"keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password"})
    @Test(expectedExceptions = IllegalStateException.class)
    public void whenSigningPrivateKeyNotSetThenBuildingThrowsException(final String senderSigningAlias,
                                                                       final String senderEncryptionAlias,
                                                                       final String recipient1EncryptionAlias,
                                                                       final String recipient2EncryptionAlias,
                                                                       final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BlobfishCryptoException {
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            new ContainerEncoderBuilder()
                    .setSigningCertificate(senderSigningCertificate)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password"})
    @Test(expectedExceptions = IllegalStateException.class)
    public void whenSigningCertificateNotSetThenBuildingThrowsException(final String entryPassword,
                                                                        final String senderSigningAlias,
                                                                        final String senderEncryptionAlias,
                                                                        final String recipient1EncryptionAlias,
                                                                        final String recipient2EncryptionAlias,
                                                                        final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BlobfishCryptoException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password"})
    @Test(expectedExceptions = IllegalStateException.class)
    public void whenOutputStreamNotSetThenBuildingThrowsException(final String entryPassword,
                                                                  final String senderSigningAlias,
                                                                  final String senderEncryptionAlias,
                                                                  final String recipient1EncryptionAlias,
                                                                  final String recipient2EncryptionAlias,
                                                                  final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BlobfishCryptoException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        new ContainerEncoderBuilder()
                .setSigningKey(privateKey)
                .setSigningCertificate(senderSigningCertificate)
                .addRecipientCertificate(senderEncryptionCertificate)
                .addRecipientCertificate(recipient1EncryptionCertificate)
                .addRecipientCertificate(recipient2EncryptionCertificate)
                .setPassword(password)
                .build();
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "blobfish-password"})
    @Test(expectedExceptions = IllegalStateException.class)
    public void whenEncryptionCertificateIsEmptyThenBuildingThrowsException(final String entryPassword,
                                                                            final String senderSigningAlias,
                                                                            final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BlobfishCryptoException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final ContainerEncoder encoder = new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .setSigningCertificate(senderSigningCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();
            Assert.assertNotNull(encoder);
        }
    }

    //------------------------------------------------------------------------------------------------------------------
    // Positive Test Cases
    //------------------------------------------------------------------------------------------------------------------
    @Test
    @Parameters({"keystore-alias-sig-sender"})
    public void whenEcSigningCertificateIsGivenThenNoExceptionThrown(final String alias) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        new ContainerEncoderBuilder()
                .setSigningCertificate(certificate);
    }

    @Test
    @Parameters({"keystore-alias-enc-sender"})
    public void whenRsaEncryptionCertificateIsGivenThenNoExceptionThrown(final String alias) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        new ContainerEncoderBuilder()
                .addRecipientCertificate(certificate);
    }

    @Test
    @Parameters({"blobfish-password"})
    public void whenNonWhitespacePasswordIsGivenNoExceptionThrown(final String password) {
        new ContainerEncoderBuilder()
                .setPassword(password);
    }

    @Test
    public void whenNonNullOutputStreamIsGivenThenNoExceptionThrown() throws IOException {
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            new ContainerEncoderBuilder()
                    .setOutputStream(baos);
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2"})
    @Test
    public void whenPasswordNotSetThenBuildingCommenced(final String entryPassword,
                                                        final String senderSigningAlias,
                                                        final String senderEncryptionAlias,
                                                        final String recipient1EncryptionAlias,
                                                        final String recipient2EncryptionAlias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BlobfishCryptoException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final ContainerEncoder encoder = new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .setSigningCertificate(senderSigningCertificate)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setOutputStream(baos)
                    .build();
            Assert.assertNotNull(encoder);
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password"})
    @Test
    public void whenAllParameterSetThenBuildingCommenced(final String entryPassword,
                                                         final String senderSigningAlias,
                                                         final String senderEncryptionAlias,
                                                         final String recipient1EncryptionAlias,
                                                         final String recipient2EncryptionAlias,
                                                         final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException, BlobfishCryptoException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final ContainerEncoder encoder = new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .setSigningCertificate(senderSigningCertificate)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();
            Assert.assertNotNull(encoder);
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password",
            "image1",
            "image2",
            "image3",
            "image4",
            "image5",
            "image6",
            "image7",
            "blobfish-path"})
    @Test
    public void testEncode(final String entryPassword,
                           final String senderSigningAlias,
                           final String senderEncryptionAlias,
                           final String recipient1EncryptionAlias,
                           final String recipient2EncryptionAlias,
                           final String password,
                           final String path1,
                           final String path2,
                           final String path3,
                           final String path4,
                           final String path5,
                           final String path6,
                           final String path7,
                           final String containerPath) throws BlobfishCryptoException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, BlobfishEncodeException {
        final Set<String> tags = new HashSet<>();
        tags.add("fish");
        tags.add("deep-sea");

        final File file = new File(containerPath);
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final FileOutputStream fos = new FileOutputStream(file)) {
            final ContainerEncoder encoder = new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .setSigningCertificate(senderSigningCertificate)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setPassword(password)
                    .setOutputStream(fos)
                    .build();
            addBlob(encoder, path1, tags);
            addBlob(encoder, path2, tags);
            addBlob(encoder, path3, tags);
            addBlob(encoder, path4, tags);
            addBlob(encoder, path5, tags);
            addBlob(encoder, path6, tags);
            addBlob(encoder, path7, tags);
            encoder.write();

            log("created blob at %s", file.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void addBlob(final ContainerEncoder encoder, final String path, final Set<String> tags) throws IOException, BlobfishCryptoException, BlobfishEncodeException {
        final File file = new File(path);
        final Metadata metadata = new Metadata();
        metadata.set(Metadata.RESOURCE_NAME_KEY, file.toString());

        try (final FileInputStream fis = new FileInputStream(file)) {
            final MediaType type = tika.getDetector().detect(TikaInputStream.get(Paths.get(path)), metadata);
            encoder.addBlob(path, tags, type.toString(), fis);
        }
    }
}
