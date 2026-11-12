fun load(path: String) {
    try {
        java.io.File(path).readText()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
