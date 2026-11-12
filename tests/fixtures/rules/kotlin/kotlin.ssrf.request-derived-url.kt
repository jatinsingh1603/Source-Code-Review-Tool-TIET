import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher

fun a(target: String) {
    // ruleid: kotlin.ssrf.request-derived-url
    URL(target)
}

fun b(request: javax.servlet.http.HttpServletRequest) {
    // ruleid: kotlin.ssrf.request-derived-url
    URL(request.getParameter("u"))
}

fun c() {
    // ok: kotlin.ssrf.request-derived-url
    URL("https://api.example.test/v1")
}
