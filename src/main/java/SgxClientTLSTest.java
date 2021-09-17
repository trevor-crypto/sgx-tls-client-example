import com.cryptodotcom.EnclaveCertVerifier;
import com.cryptodotcom.types.EnclaveQuoteStatus;
import com.google.gson.Gson;
import org.spongycastle.jce.provider.BouncyCastleProvider;


import javax.net.ssl.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

class SgxClientTLSTest {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            // init keystore with intel sgx CA added
            final char[] password = "123456".toCharArray();
            ClassLoader loader = ClassLoader.getSystemClassLoader();
            final InputStream keyStoreStream = loader.getResourceAsStream("IntelCACert.bks");
            KeyStore keyStore = KeyStore.getInstance("BKS", "SC");
            keyStore.load(keyStoreStream, password);
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, password);

            InputStream attestationReportCACertStream = loader.getResourceAsStream("AttestationReportSigningCACert.der");

            // Create enclave tls client
            Set<EnclaveQuoteStatus> validStatuses = new HashSet<>();
            validStatuses.add(EnclaveQuoteStatus.OK);
            validStatuses.add(EnclaveQuoteStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED);
            validStatuses.add(EnclaveQuoteStatus.SW_HARDENING_NEEDED);
            final EnclaveCertVerifier ecv = new EnclaveCertVerifier(validStatuses, Duration.ofSeconds(86400), attestationReportCACertStream);
            final TrustManager[] trustManagers = new EnclaveCertVerifier[]{ecv};

            // create ssl context
            final SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, SecureRandom.getInstanceStrong());

            SSLSocketFactory factory = sslContext.getSocketFactory();

            SSLSocket socket = (SSLSocket) factory.createSocket("20.205.161.251", 60001);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // sending Ping request
            Gson gson = new Gson();
            String pingReq = gson.toJson("ping");
            System.out.println("ping req: [" + pingReq + "]");
            // write req length
            out.writeShort(pingReq.length());
            System.out.println("Writing PING request...");
            // write json
            out.writeBytes(pingReq);
            out.flush();

            // reading response, should be Pong
            // read 2 byte length
            short responseLength = in.readShort();
            assert responseLength == 6;
            System.out.println(responseLength);
            byte[] responseData = new byte[responseLength];
            // read response
            int nBytes = in.read(responseData);
            String response = new String(responseData);
            assert response.equals("pong");
            System.out.println("Result: " + response);

            out.close();
            in.close();
            socket.close();
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | KeyManagementException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }
}