import com.cryptodotcom.EnclaveCertVerifier
import com.cryptodotcom.types.EnclaveQuoteStatus
import com.google.gson.Gson
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import java.time.Duration
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

internal object SgxClientTLSTest {
    @JvmStatic
    fun main(args: Array<String>) {
        Security.addProvider(BouncyCastleProvider())
        try {
            // init keystore with intel sgx CA added
            val password = "123456".toCharArray()
            val loader = ClassLoader.getSystemClassLoader()
            val keyStoreStream = loader.getResourceAsStream("IntelCACert.bks")
            val keyStore = KeyStore.getInstance("BKS", "SC")
            keyStore.load(keyStoreStream, password)
            val keyManagerFactory = KeyManagerFactory.getInstance("SunX509")
            keyManagerFactory.init(keyStore, password)
            val attestationReportCACertStream = loader.getResourceAsStream("AttestationReportSigningCACert.der")

            // Create enclave tls client
            val validStatuses: MutableSet<EnclaveQuoteStatus> = HashSet()
            validStatuses.add(EnclaveQuoteStatus.OK)
            validStatuses.add(EnclaveQuoteStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED)
            validStatuses.add(EnclaveQuoteStatus.SW_HARDENING_NEEDED)
            val ecv = EnclaveCertVerifier(validStatuses, Duration.ofSeconds(86400), attestationReportCACertStream)
            val trustManagers: Array<EnclaveCertVerifier> = arrayOf(ecv)

            // create ssl context
            val sslContext = SSLContext.getInstance("TLSv1.3")
            sslContext.init(keyManagerFactory.keyManagers, trustManagers, SecureRandom.getInstanceStrong())
            val factory = sslContext.socketFactory
            val socket = factory.createSocket("20.205.161.251", 60001) as SSLSocket
            val dos = DataOutputStream(socket.outputStream)
            val dis = DataInputStream(socket.inputStream)

            // sending Ping request
            val gson = Gson()
            val pingReq = gson.toJson("ping")
            println("ping req: [$pingReq]")
            // write req length
            dos.writeShort(pingReq.length)
            println("Writing PING request...")
            // write json
            dos.writeBytes(pingReq)
            dos.flush()

            // reading response, should be Pong
            // read 2 byte length
            val responseLength = dis.readShort()
            assert(responseLength.toInt() == 6)
            println(responseLength)
            val responseData = ByteArray(responseLength.toInt())
            // read response
            dis.read(responseData)
            val response = String(responseData)
            assert(response == "pong")
            println("Result: $response")
            dos.close()
            dis.close()
            socket.close()
        } catch (e: IOException) {
            e.printStackTrace()
        } catch (e: CertificateException) {
            e.printStackTrace()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        } catch (e: UnrecoverableKeyException) {
            e.printStackTrace()
        } catch (e: KeyManagementException) {
            e.printStackTrace()
        } catch (e: NoSuchProviderException) {
            e.printStackTrace()
        }
    }
}