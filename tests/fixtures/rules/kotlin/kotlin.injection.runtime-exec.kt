import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher

fun a(host: String) {
    // ruleid: kotlin.injection.runtime-exec
    Runtime.getRuntime().exec("ping -c1 " + host)
}

fun b(host: String) {
    // ruleid: kotlin.injection.runtime-exec
    Runtime.getRuntime().exec("ping -c1 $host")
}

fun c() {
    // ok: kotlin.injection.runtime-exec
    Runtime.getRuntime().exec("uptime")
}
