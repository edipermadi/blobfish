package com.github.edipermadi.security.blobfish;

import com.github.edipermadi.security.blobfish.generated.BlobfishProto;
import com.google.protobuf.ByteString;
import org.apache.commons.io.output.ByteArrayOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Container Encoder Version 1
 *
 * @author Edi Permadi
 */
final class ContainerEncoderV1 implements ContainerEncoder {
    private static final String KEY_PROTECTION_ALGORITHM = "RSA/None/OAEPWithSHA256AndMGF1Padding";
    private static final String CIPHERING_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SIGNING_ALGORITHM = "SHA256withECDSA";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA256";

    private final X509Certificate signingCertificate;
    private final PrivateKey signingPrivateKey;
    private final char[] password;
    private final List<X509Certificate> recipientCertificates;
    private final OutputStream outputStream;
    private byte[] keyBytes = new byte[16];
    private byte[] ivBytes = new byte[16];
    private final AtomicBoolean initialized = new AtomicBoolean(false);

    public ContainerEncoderV1(ContainerEncoderBuilder builder) {
        signingPrivateKey = builder.signingPrivateKey;
        signingCertificate = builder.signingCertificate;
        password = builder.password;
        recipientCertificates = builder.recipientCertificates;
        outputStream = builder.outputStream;
    }

    @Override
    public ContainerEncoderV1 addBlob(final String path, final List<String> tags, final String mimeType,
                                      final InputStream inputStream) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, SignatureException {

        final BlobfishProto.Blobfish.Body.Entry payload = createEntry(inputStream);
        final BlobfishProto.Blobfish.Body.Entry metadata = createEntry();
        return this;
    }

    private void init() {
        if (!initialized.getAndSet(true)) {
            final
        }
    }

    private BlobfishProto.Blobfish.Body.Entry createEntry(final InputStream inputStream) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        /* initialize cipher */
        final Cipher cipher = Cipher.getInstance(CIPHERING_ALGORITHM);
        final SecretKeySpec cipherKeySpec = new SecretKeySpec(keyBytes, "AES");
        final IvParameterSpec cipherIvSpec = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKeySpec, cipherIvSpec);

        /* initialize MAC */
        final SecretKeySpec macKeySpec = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
        final Mac macCalculator = Mac.getInstance(MAC_ALGORITHM);
        macCalculator.init(macKeySpec);

        /* initialize signer */
        final Signature signer = Signature.getInstance(SIGNING_ALGORITHM);
        signer.initSign(signingPrivateKey);

        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
             final CipherOutputStream cipherOutputStream = new CipherOutputStream(baos, cipher)) {

            /* process input stream */
            final byte[] buffer = new byte[8192];
            int r = 0;
            while ((r = inputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, r);
                macCalculator.update(buffer, 0, r);
                signer.update(buffer, 0, r);
            }
            cipherOutputStream.flush();


            final ByteString mac = ByteString.copyFrom(macCalculator.doFinal());
            final ByteString signature = ByteString.copyFrom(signer.sign());
            final ByteString ciphertext = BlobfishProto.Blobfish.Body.Payload
                    .newBuilder()
                    .setData(ByteString.copyFrom(baos.toByteArray()))
                    .build()
                    .toByteString();

            return BlobfishProto.Blobfish.Body.Entry.newBuilder()
                    .setCiphertext(ciphertext)
                    .setHmac(mac)
                    .setSignature(signature)
                    .build();
        }
    }

    @Override
    public void close() throws IOException {

    }
}
