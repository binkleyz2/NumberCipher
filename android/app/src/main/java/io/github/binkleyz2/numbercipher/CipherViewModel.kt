package io.github.binkleyz2.numbercipher

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Build
import android.os.PersistableBundle
import android.os.Process
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.binkleyz2.numbercipher.crypto.CancelledException
import io.github.binkleyz2.numbercipher.crypto.CipherEngine
import io.github.binkleyz2.numbercipher.crypto.CipherException
import io.github.binkleyz2.numbercipher.crypto.DeviceProfile
import io.github.binkleyz2.numbercipher.crypto.Pbkdf2
import io.github.binkleyz2.numbercipher.crypto.WorkProgress
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

enum class Mode { Encrypt, Decrypt }

class CipherViewModel(app: Application) : AndroidViewModel(app) {

    /**
     * One dedicated worker thread at raised priority. On phones with big and little cores,
     * the scheduler tends to keep a busy high-priority thread on a fast core.
     */
    private val worker = Executors.newSingleThreadExecutor { r ->
        Thread({
            try {
                Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_DISPLAY)
            } catch (_: Exception) {
                runCatching { Process.setThreadPriority(Process.THREAD_PRIORITY_DISPLAY) }
            }
            r.run()
        }, "cipher-work")
    }.asCoroutineDispatcher()

    private val kdf = Pbkdf2.best()
    private val engine = CipherEngine(kdf, DeviceProfile.cpuClock())
    private val cancelFlag = AtomicBoolean(false)
    private var workJob: Job? = null
    private var clearJob: Job? = null
    private var copiedText: String? = null

    var mode by mutableStateOf(Mode.Encrypt); private set
    var input by mutableStateOf("")
    var passphrase by mutableStateOf("")
    var confirm by mutableStateOf("")
    var output by mutableStateOf(""); private set
    var error by mutableStateOf<String?>(null); private set
    var busy by mutableStateOf(false); private set
    var copied by mutableStateOf(false); private set
    var profile by mutableStateOf<DeviceProfile?>(null); private set

    private val _progress = MutableStateFlow<WorkProgress?>(null)
    val progress: StateFlow<WorkProgress?> = _progress

    init {
        // Measure this device once, in the background, for the speed panel and decrypt estimates.
        viewModelScope.launch {
            profile = withContext(worker) { DeviceProfile.measure(getApplication(), kdf) }
        }
    }

    val canRun: Boolean
        get() = !busy && input.isNotBlank() && passphrase.isNotEmpty() &&
            (mode == Mode.Decrypt || passphrase == confirm)

    val mismatch: Boolean get() = mode == Mode.Encrypt && confirm.isNotEmpty() && confirm != passphrase

    fun selectMode(m: Mode) {
        if (m == mode || busy) return
        mode = m
        clearAll()
    }

    fun run() {
        if (!canRun) return
        val m = mode
        val text = input
        val pw = passphrase
        cancelFlag.set(false)
        busy = true
        error = null
        output = ""
        copied = false
        // Decrypting: show an up-front estimate from the measured speed until live timing takes over.
        val estimate = if (m == Mode.Decrypt) {
            val rounds = CipherEngine.roundsIn(text)
            val p = profile
            if (rounds != null && p != null) Math.ceil(p.secondsFor(rounds)).toInt() else null
        } else CipherEngine.TARGET_SECONDS.toInt()
        _progress.value = WorkProgress(0f, estimate, 0)

        workJob = viewModelScope.launch {
            try {
                val result = withContext(worker) {
                    val onProgress = { p: WorkProgress ->
                        _progress.value = if (p.secondsLeft == null) p.copy(secondsLeft = _progress.value?.secondsLeft) else p
                    }
                    if (m == Mode.Encrypt) engine.encrypt(text, pw, isCancelled = cancelFlag::get, onProgress = onProgress)
                    else engine.decrypt(text, pw, isCancelled = cancelFlag::get, onProgress = onProgress)
                }
                output = result
            } catch (_: CancelledException) {
                // User cancelled; nothing to report.
            } catch (e: CipherException) {
                error = e.message
            } catch (_: Exception) {
                error = "Something went wrong inside the encryption engine."
            } finally {
                busy = false
                _progress.value = null
            }
        }
    }

    fun cancel() = cancelFlag.set(true)

    fun clearAll() {
        if (busy) return
        input = ""; passphrase = ""; confirm = ""; output = ""; error = null; copied = false
    }

    fun paste() {
        val cm = getApplication<Application>().getSystemService(ClipboardManager::class.java) ?: return
        val text = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(getApplication())?.toString()
        if (!text.isNullOrBlank()) input = text.trim()
    }

    /** Copies the result, marked sensitive (hidden from clipboard previews), and clears it after 60 s. */
    fun copy() {
        val cm = getApplication<Application>().getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText("Cipherwords", output)
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
        cm.setPrimaryClip(clip)
        copiedText = output
        copied = true
        clearJob?.cancel()
        clearJob = viewModelScope.launch {
            delay(60_000)
            clearClipboardIfOurs()
            copied = false
        }
    }

    private fun clearClipboardIfOurs() {
        val ours = copiedText ?: return
        val cm = getApplication<Application>().getSystemService(ClipboardManager::class.java) ?: return
        // In the background Android hides the clipboard from apps (returns null); clear anyway then.
        val current = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
        if (current == null || current == ours) {
            runCatching {
                if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip() else cm.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }
        copiedText = null
    }

    override fun onCleared() {
        cancelFlag.set(true)
        clearClipboardIfOurs() // don't leave a code on the clipboard after the app closes
        worker.close()
        super.onCleared()
    }
}
