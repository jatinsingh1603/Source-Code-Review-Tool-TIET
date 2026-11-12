import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher

fun a(input: java.io.InputStream): Any {
    // ruleid: kotlin.deser.object-input-stream
    return ObjectInputStream(input).readObject()
}

fun b(text: String): Any {
    // ok: kotlin.deser.object-input-stream
    return text.length
}
