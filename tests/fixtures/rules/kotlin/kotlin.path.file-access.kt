import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher

fun a(name: String) {
    // ruleid: kotlin.path.file-access
    File("/srv/files/" + name)
}

fun b(request: javax.servlet.http.HttpServletRequest) {
    // ruleid: kotlin.path.file-access
    File(request.getParameter("f"))
}

fun c() {
    // ok: kotlin.path.file-access
    File("/srv/files/readme.txt")
}
