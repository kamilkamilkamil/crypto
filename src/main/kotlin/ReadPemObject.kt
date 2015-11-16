import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.util.io.pem.PemObject
import java.io.Reader
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

object ReadPemObject {

    fun apply(reader: Reader): PemObject {

        val parser = PEMParser(reader)

        val pemObj = parser.readPemObject()

        return pemObj

    }

}