import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.util.io.pem.PemObject
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec

object ConvertPemObject {

    fun apply(pemObject: PemObject): PrivateKey {

        val kf = KeyFactory.getInstance("RSA")

        val pemKeys = pemObject as PEMKeyPair

        val byteArr = pemKeys.privateKeyInfo.encoded

        val spec = PKCS8EncodedKeySpec(byteArr)

        val key = kf.generatePrivate(spec)

        return key

    }

}
