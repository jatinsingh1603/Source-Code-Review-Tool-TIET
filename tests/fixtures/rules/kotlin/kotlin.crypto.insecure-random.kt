import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher

fun a(): Int {
    // ruleid: kotlin.crypto.insecure-random
    return Random().nextInt()
}

fun b(): Double {
    // ruleid: kotlin.crypto.insecure-random
    return Math.random()
}

fun c(): Int {
    // ok: kotlin.crypto.insecure-random
    return SecureRandom().nextInt()
}
