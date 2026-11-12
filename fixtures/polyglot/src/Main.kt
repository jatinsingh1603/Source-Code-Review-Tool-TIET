import java.io.File

fun load(name: String): String {
    return File("/srv/data/" + name).readText()  // PG-VULN-003
}
