import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher

fun a(): Any {
    // ruleid: kotlin.crypto.weak-algorithm
    return MessageDigest.getInstance("MD5")
}

fun b(): Any {
    // ruleid: kotlin.crypto.weak-algorithm
    return Cipher.getInstance("AES/ECB/PKCS5Padding")
}

fun c(): Any {
    // ok: kotlin.crypto.weak-algorithm
    return MessageDigest.getInstance("SHA-256")
}
