## Blobfish Library Usage

## Encoding Blobs into Container

```java
import com.github.edipermadi.security.blobfish.codec.ContainerEncoder;
import com.github.edipermadi.security.blobfish.codec.ContainerEncoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishEncodeException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;

public final class EncodingExample {
    public static void main(String[] args) throws IOException, BlobfishEncodeException, BlobfishCryptoException {
        final String password = getPassword();
        final PrivateKey senderSigningPrivateKey = getSenderSigningPrivateKey();
        final X509Certificate senderSigningCertificate = getSenderSigningCertificate();
        final X509Certificate senderEncryptionCertificate = getSenderEncryptionCertificate();
        final X509Certificate recipientEncryptionCertificate = getRecipientEncryptionCertificate();

        final String path = getPath();
        final String mimeType = getMimeType();
        final Set<String> tags = getTags();
        final InputStream inputStream = getInputStream();

        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final ContainerEncoder encoder = new ContainerEncoderBuilder()
                    .setSigningKey(senderSigningPrivateKey)
                    .setSigningCertificate(senderSigningCertificate)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipientEncryptionCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();

            encoder.addBlob(path, tags, mimeType, inputStream);
            /* add another blob here */
            encoder.write();
            
            /* this is the final blobfish container payload */
            final byte[] containerPayload = baos.toByteArray();
        }
    }
}

```

## Decoding Blob from Container

Blob can be extracted from container by:
- password
- recipient certificate and private key

```java
import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoder;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;

public final class DecodingExample {
    public static void main(String[] args) throws IOException, CertificateException, BlobfishDecodeException, BlobfishCryptoException {
        final InputStream containerInputStream = getInputStream();
        final int blobId = 0; /* blobId spans from 0 .. n */
        final String password = getPassword();
        final X509Certificate certificate = getRecipientCertificate();
        final PrivateKey privateKey = getRecipientPrivateKey();
        
        final ContainerDecoder decoder = new ContainerDecoderBuilder()
                .setInputStream(containerInputStream)
                .build();

        /* get blob with password */
        final Blob blob1 = decoder.getBlob(blobId, password);
        
        /* get blob with private-key */
        final Blob blob2 = decoder.getBlob(blobId, certificate, privateKey);
        
        /* retrieve blob metadata and payload */
        final Blob.Metadata metadata = blob1.getMetadata();
        final String path = metadata.getPath();
        final String mimeType = metadata.getMimeType();
        final Set<String> tags = metadata.getTags();
        final byte[] payload = blob1.getPayload();

    }
}
```