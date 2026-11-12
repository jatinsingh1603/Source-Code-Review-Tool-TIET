import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher

fun a(f: javax.xml.parsers.DocumentBuilderFactory) {
    // ruleid: kotlin.xxe.parser-features
    f.setFeature("http://xml.org/sax/features/external-general-entities", true)
}

fun b(f: javax.xml.parsers.DocumentBuilderFactory) {
    // ruleid: kotlin.xxe.parser-features
    f.setExpandEntityReferences(true)
}

fun c(f: javax.xml.parsers.DocumentBuilderFactory) {
    // ok: kotlin.xxe.parser-features
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
}
