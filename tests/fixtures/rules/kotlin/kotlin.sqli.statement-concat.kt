import java.io.File
import java.io.ObjectInputStream
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher

fun a(stmt: java.sql.Statement, id: String) {
    // ruleid: kotlin.sqli.statement-concat
    stmt.executeQuery("SELECT * FROM t WHERE id = " + id)
}

fun b(stmt: java.sql.Statement, id: String) {
    // ruleid: kotlin.sqli.statement-concat
    stmt.executeQuery("SELECT * FROM t WHERE id = $id")
}

fun c(conn: java.sql.Connection, id: String) {
    // ok: kotlin.sqli.statement-concat
    val ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?")
    ps.setString(1, id)
}
