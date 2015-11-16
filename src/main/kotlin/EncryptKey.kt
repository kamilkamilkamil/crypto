import org.bouncycastle.openssl.PKCS8Generator
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import java.security.PrivateKey
import java.security.SecureRandom

object EncryptKey {

    fun apply(key: PrivateKey, password: String): PemObject {

        val eb = JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES)

        eb.setRandom(SecureRandom())

        eb.setPasssword(password.toCharArray())

        val oe = eb.build()

        val gen = JcaPKCS8Generator(key, oe)

        val pemObj = gen.generate()

        return pemObj

    }

}
