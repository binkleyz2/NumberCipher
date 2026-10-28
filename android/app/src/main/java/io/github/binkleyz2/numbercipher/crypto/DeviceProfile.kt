package io.github.binkleyz2.numbercipher.crypto

import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.PowerManager
import java.io.File

/**
 * What this phone or tablet brings to key stretching, and how fast it actually runs it.
 *
 * Why only one CPU core matters: PBKDF2 is a single chain where each step needs the
 * previous one, so it can't be split across cores, and an NPU or GPU can't run it (they
 * accelerate matrix math, not SHA-256 chains). What matters is the fastest core's clock
 * speed and whether it has SHA-256 instructions, which nearly all 64-bit ARM phones do.
 */
data class DeviceProfile(
    val device: String,
    val chip: String?,
    val abi: String,
    val coreCount: Int,
    /** Distinct maximum core speeds in MHz, fastest first (e.g. one big, three mid, four little). */
    val clusterMhz: List<Int>,
    val implementation: String,
    val hardwareSha: Boolean,
    val roundsPerSecond: Double,
    val thermalNote: String?,
) {
    /** Rounds a new code gets here (10 s of work, never below the minimum). */
    val roundsForNewCode: Long get() = maxOf((roundsPerSecond * CipherEngine.TARGET_SECONDS).toLong(), CipherEngine.MIN_ROUNDS.toLong())

    fun secondsFor(rounds: Int): Double = rounds / roundsPerSecond

    companion object {
        /**
         * Measures real speed on the calling thread (call it from the worker thread). Phones
         * start slow and raise their clock under load, and may first run new work on a small
         * core, so it warms up for ~0.4 s and then keeps the best of three short runs.
         */
        fun measure(context: Context, kdf: Pbkdf2 = Pbkdf2.best()): DeviceProfile {
            val clock = cpuClock()
            val salt = ByteArray(16) { 7 }
            val pw = "benchmark".toByteArray()
            val out = ByteArray(32)
            fun runFor(seconds: Double): Double {
                val start = clock()
                val limit = (seconds * 1e9).toLong()
                val done = kdf.derive(pw, salt, Int.MAX_VALUE, 16_384, out, object : ChunkCallback {
                    override fun onChunk(done: Int) = if (clock() - start >= limit) ChunkCallback.STOP else ChunkCallback.CONTINUE
                })
                return done / ((clock() - start) / 1e9)
            }
            runFor(0.4)
            val speed = (1..3).maxOf { runFor(0.2) }

            val socModel = if (Build.VERSION.SDK_INT >= 31) Build.SOC_MODEL.takeUnless { it.isBlank() || it == Build.UNKNOWN } else null
            val socMaker = if (Build.VERSION.SDK_INT >= 31) Build.SOC_MANUFACTURER.takeUnless { it.isBlank() || it == Build.UNKNOWN } else null
            val chip = listOfNotNull(socMaker, socModel).joinToString(" ").ifBlank { Build.HARDWARE.takeUnless { it.isBlank() } }

            return DeviceProfile(
                device = "${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}",
                chip = chip,
                abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown",
                coreCount = Runtime.getRuntime().availableProcessors(),
                clusterMhz = coreClusters(),
                implementation = kdf.name,
                hardwareSha = kdf.name.contains("instructions") || kdf.name.contains("extensions"),
                roundsPerSecond = speed,
                thermalNote = thermalNote(context),
            )
        }

        /** CPU time of the calling thread, falling back to wall time if the device doesn't report it. */
        fun cpuClock(): () -> Long =
            if (Debug.threadCpuTimeNanos() >= 0) ({ Debug.threadCpuTimeNanos() }) else ({ System.nanoTime() })

        private fun coreClusters(): List<Int> = try {
            File("/sys/devices/system/cpu").listFiles { f -> f.name.matches(Regex("cpu\\d+")) }.orEmpty()
                .mapNotNull { File(it, "cpufreq/cpuinfo_max_freq").takeIf(File::canRead)?.readText()?.trim()?.toIntOrNull() }
                .map { it / 1000 }
                .distinct()
                .sortedDescending()
        } catch (_: Exception) {
            emptyList()
        }

        private fun thermalNote(context: Context): String? {
            if (Build.VERSION.SDK_INT < 29) return null
            val pm = context.getSystemService(PowerManager::class.java) ?: return null
            return when (pm.currentThermalStatus) {
                PowerManager.THERMAL_STATUS_NONE, PowerManager.THERMAL_STATUS_LIGHT -> null
                PowerManager.THERMAL_STATUS_MODERATE -> "The device is warm and may be running slower than usual."
                else -> "The device is hot and is slowing itself down. Timings will be longer until it cools."
            }
        }
    }
}
