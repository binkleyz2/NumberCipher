package io.github.binkleyz2.numbercipher

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.binkleyz2.numbercipher.crypto.CipherEngine
import io.github.binkleyz2.numbercipher.crypto.DeviceProfile
import java.util.Locale
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Keep codes and numbers out of screenshots, screen recordings and the recent-apps preview.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (intent?.getBooleanExtra(SelfTest.EXTRA, false) == true) thread(name = "selftest") { SelfTest.run() }
        setContent { NumberCipherTheme { CipherScreen() } }
    }
}

/** Launch check used by the build pipeline: `am start ... --ez nc_selftest true`, then read logcat. */
object SelfTest {
    const val EXTRA = "nc_selftest"
    // Made by recover.py (the Mac app's format) with passphrase "maple orbit tundra swivel".
    private const val MAC_FORMAT_CODE =
        "ACAAA EKDQA DBGEF LEMLQ DKHGL GKKPB AMQKD EBAAC LAMBL DQBRP LQLPN GHRNL CJNPN CQNHE DFKJL GHNNK KHMMR " +
        "CGMJL CMFNB KKBDH KEAQB JLBDE FEFPA DRPQP KMELF JEGCM KRJHR CNPNJ NJDDH PQHRK RNNEF RLJCD EM"

    fun run() {
        val ok = try {
            val e = CipherEngine()
            val a = e.decrypt(MAC_FORMAT_CODE, "maple orbit tundra swivel") == "4111 2222 3333 4444\n555-0199"
            val b = e.decrypt(e.encrypt("8675 309", "self test", fixedRounds = 300_000), "self test") == "8675 309"
            a && b
        } catch (t: Throwable) {
            Log.e("NumberCipher", "SELFTEST error", t); false
        }
        Log.i("NumberCipher", "SELFTEST ${if (ok) "PASS" else "FAIL"} kdf=${io.github.binkleyz2.numbercipher.crypto.Pbkdf2.best().name}")
    }
}

@Composable
fun NumberCipherTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val ctx = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors, content = content)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CipherScreen(vm: CipherViewModel = viewModel()) {
    val context = LocalContext.current
    val progress by vm.progress.collectAsStateWithLifecycle()
    var showInfo by remember { mutableStateOf(false) }
    var showPass by remember { mutableStateOf(false) }
    val encrypt = vm.mode == Mode.Encrypt
    val mono = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace)

    // Keep the screen awake while working, so the device doesn't sleep mid-encryption.
    val activity = context as? ComponentActivity
    LaunchedEffect(vm.busy) {
        val flag = WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
        if (vm.busy) activity?.window?.addFlags(flag) else activity?.window?.clearFlags(flag)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Number Cipher") },
                actions = {
                    IconButton(onClick = { showInfo = true }) {
                        Icon(Icons.Outlined.Info, contentDescription = "Device speed and about")
                    }
                },
            )
        },
    ) { inner ->
        Box(Modifier.fillMaxSize().padding(inner).imePadding(), contentAlignment = Alignment.TopCenter) {
            Column(
                Modifier
                    .widthIn(max = 640.dp) // comfortable line length on tablets and unfolded foldables
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    Mode.entries.forEachIndexed { i, m ->
                        SegmentedButton(
                            selected = vm.mode == m,
                            onClick = { vm.selectMode(m) },
                            enabled = !vm.busy,
                            shape = SegmentedButtonDefaults.itemShape(i, Mode.entries.size),
                        ) { Text(m.name) }
                    }
                }

                OutlinedTextField(
                    value = vm.input,
                    onValueChange = { vm.input = it },
                    label = { Text(if (encrypt) "Numbers to encrypt" else "Letter code to decrypt") },
                    textStyle = mono,
                    minLines = 3,
                    readOnly = vm.busy,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Ascii,
                        capitalization = if (encrypt) KeyboardCapitalization.None else KeyboardCapitalization.Characters,
                        autoCorrectEnabled = false,
                    ),
                    trailingIcon = if (!encrypt && !vm.busy) ({ TextButton(onClick = vm::paste) { Text("Paste") } }) else null,
                    modifier = Modifier.fillMaxWidth(),
                )

                OutlinedTextField(
                    value = vm.passphrase,
                    onValueChange = { vm.passphrase = it },
                    label = { Text("Passphrase") },
                    singleLine = true,
                    enabled = !vm.busy,
                    visualTransformation = if (showPass) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password, autoCorrectEnabled = false,
                        imeAction = if (encrypt) ImeAction.Next else ImeAction.Done,
                    ),
                    trailingIcon = { TextButton(onClick = { showPass = !showPass }) { Text(if (showPass) "Hide" else "Show") } },
                    modifier = Modifier.fillMaxWidth(),
                )

                if (encrypt) {
                    OutlinedTextField(
                        value = vm.confirm,
                        onValueChange = { vm.confirm = it },
                        label = { Text("Confirm passphrase") },
                        singleLine = true,
                        enabled = !vm.busy,
                        isError = vm.mismatch,
                        supportingText = if (vm.mismatch) ({ Text("Passphrases don't match") }) else null,
                        visualTransformation = if (showPass) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false, imeAction = ImeAction.Done),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    StrengthMeter(vm.passphrase)
                }

                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Button(onClick = vm::run, enabled = vm.canRun) { Text(vm.mode.name) }
                    OutlinedButton(onClick = vm::clearAll, enabled = !vm.busy) { Text("Clear All") }
                }

                progress?.let { p ->
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        LinearProgressIndicator(progress = { p.fraction }, modifier = Modifier.fillMaxWidth())
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            val left = p.secondsLeft
                            Text(
                                when {
                                    left == null -> "Strengthening key…"
                                    left > 0 -> "Strengthening key — about ${formatSeconds(left)} left"
                                    else -> "Finishing…"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(onClick = vm::cancel) { Text("Cancel") }
                        }
                    }
                }

                vm.error?.let { msg ->
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Outlined.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error)
                        Text(msg, color = MaterialTheme.colorScheme.error)
                    }
                }

                if (vm.output.isNotEmpty()) {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh)) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(if (encrypt) "Letter code" else "Numbers", fontWeight = FontWeight.Bold)
                            SelectionContainer { Text(vm.output, style = mono) }
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(onClick = vm::copy) { Text(if (vm.copied) "Copied — clears in 60s" else "Copy") }
                                if (encrypt) {
                                    // Only the letter code is offered for sharing, never the decrypted numbers.
                                    OutlinedButton(onClick = {
                                        val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, vm.output)
                                        context.startActivity(Intent.createChooser(send, "Share letter code"))
                                    }) { Text("Share") }
                                }
                            }
                        }
                    }
                }

                Spacer(Modifier.height(4.dp))
                Text(
                    "AES-256-GCM · PBKDF2-SHA256, ~10 s of work on this device · every encryption is unique",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
            }
        }
    }

    if (showInfo) InfoDialog(vm.profile) { showInfo = false }
}

@Composable
private fun StrengthMeter(passphrase: String) {
    val bits = CipherEngine.strengthBits(passphrase)
    val (label, color) = when {
        passphrase.isEmpty() -> "Passphrase strength" to MaterialTheme.colorScheme.onSurfaceVariant
        bits < 40 -> "Weak — use a longer passphrase" to MaterialTheme.colorScheme.error
        bits < 60 -> "Fair" to Color(0xFFCA5010)
        bits < 80 -> "Strong" to Color(0xFF2E7D32)
        else -> "Very strong" to Color(0xFF2E7D32)
    }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp),
        modifier = Modifier.semantics { contentDescription = "Passphrase strength: $label" }) {
        LinearProgressIndicator(
            progress = { (minOf(bits, 100.0) / 100).toFloat() },
            color = color,
            modifier = Modifier.widthIn(max = 140.dp).fillMaxWidth(0.4f),
        )
        Text(label, style = MaterialTheme.typography.bodySmall, color = color)
    }
}

@Composable
private fun InfoDialog(profile: DeviceProfile?, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
        title = { Text("This device") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (profile == null) {
                    Text("Measuring speed…")
                } else {
                    InfoRow("Device", profile.device)
                    profile.chip?.let { InfoRow("Chip", it) }
                    InfoRow("CPU", buildString {
                        append("${profile.coreCount} cores")
                        if (profile.clusterMhz.isNotEmpty()) append(", up to " + profile.clusterMhz.joinToString(" / ") { String.format(Locale.US, "%.2f GHz", it / 1000.0) })
                        append(" (${profile.abi})")
                    })
                    InfoRow("SHA-256", profile.implementation)
                    InfoRow("Speed", "${formatRounds(profile.roundsPerSecond)} rounds per second")
                    InfoRow("New codes", "about ${formatRounds(profile.roundsForNewCode.toDouble())} rounds (10 s)")
                    InfoRow("Other codes", "A code made with 25 million rounds takes about ${formatSeconds(Math.ceil(profile.secondsFor(25_000_000)).toInt())} here")
                    profile.thermalNote?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    "Key stretching is one long chain of SHA-256 steps, so it runs on a single CPU core. " +
                        "Extra cores, the GPU and the NPU can't speed it up. Each code stores its own round count, " +
                        "so codes from the Mac, Windows and other phones all decrypt here; a code made on a faster " +
                        "device simply takes longer on a slower one.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text("Version ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
    )
}

@Composable
private fun InfoRow(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

private fun formatSeconds(s: Int): String = if (s < 90) "$s s" else "${s / 60} min ${s % 60} s"

private fun formatRounds(r: Double): String = when {
    r >= 1e6 -> String.format(Locale.US, "%.1f million", r / 1e6)
    else -> String.format(Locale.US, "%,.0f", r)
}
