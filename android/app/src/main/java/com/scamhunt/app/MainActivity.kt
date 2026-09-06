package com.scamhunt.app

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.ContentValues
import android.content.Intent
import android.net.Uri
import android.os.Environment
import android.os.Bundle
import android.provider.MediaStore
import android.webkit.JavascriptInterface
import android.webkit.DownloadListener
import android.view.Window
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import android.util.Base64
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private var fileChooserCallback: ValueCallback<Array<Uri>>? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        hideStatusBar(window)
        setContentView(R.layout.activity_main)

        webView = findViewById(R.id.scamhunt_webview)
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = true
            allowContentAccess = true
            builtInZoomControls = false
            displayZoomControls = false
            mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
        }
        webView.addJavascriptInterface(AndroidFileSaver(), "AndroidFileSaver")
        webView.setDownloadListener(DownloadListener { url, userAgent, contentDisposition, mimeType, _ ->
            saveDownloadUrl(url, contentDisposition, mimeType)
        })
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                return openExternalUrl(request.url)
            }
        }
        webView.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                webView: WebView,
                filePathCallback: ValueCallback<Array<Uri>>?,
                fileChooserParams: FileChooserParams?
            ): Boolean {
                fileChooserCallback?.onReceiveValue(null)
                fileChooserCallback = filePathCallback
                return try {
                    val intent = fileChooserParams?.createIntent() ?: Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "*/*"
                    }
                    startActivityForResult(intent, FILE_CHOOSER_REQUEST)
                    true
                } catch (_: ActivityNotFoundException) {
                    fileChooserCallback = null
                    false
                }
            }
        }
        webView.loadUrl("file:///android_asset/index.html")

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) webView.goBack() else finish()
            }
        })
    }

    private fun openExternalUrl(uri: Uri): Boolean {
        if (uri.scheme == "file" || uri.scheme == "about") return false
        return try {
            startActivity(Intent(Intent.ACTION_VIEW, uri))
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }

    private fun saveDownloadUrl(url: String, contentDisposition: String?, mimeType: String?) {
        if (url.startsWith("data:")) {
            val separator = url.indexOf(',')
            if (separator > 0) {
                val payload = url.substring(separator + 1)
                val bytes = if (url.substring(0, separator).contains(";base64")) {
                    Base64.decode(payload, Base64.DEFAULT)
                } else {
                    Uri.decode(payload).toByteArray(Charsets.UTF_8)
                }
                saveToDownloads(resolveFileName(contentDisposition, mimeType), mimeType, bytes)
            }
        }
    }

    private fun resolveFileName(contentDisposition: String?, mimeType: String?): String {
        val supplied = contentDisposition?.substringAfter("filename=", "")?.trim('"', '\'')
        if (!supplied.isNullOrBlank()) return supplied
        return if (mimeType == "application/json") "ScamHunt_Evidence_Package.json" else "ScamHunt_Incident_Report.txt"
    }

    private fun saveToDownloads(fileName: String, mimeType: String?, bytes: ByteArray): Boolean {
        return try {
            val safeName = fileName.replace(Regex("[^A-Za-z0-9._-]"), "_")
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, safeName)
                put(MediaStore.Downloads.MIME_TYPE, mimeType ?: "application/octet-stream")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = contentResolver
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return false
            val output = resolver.openOutputStream(uri) ?: run {
                resolver.delete(uri, null, null)
                showDownloadMessage("Could not save the report. Please try again.")
                return false
            }
            output.use { it.write(bytes) }
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
            showDownloadMessage("Report saved successfully.\n$safeName")
            true
        } catch (_: Exception) {
            showDownloadMessage("Could not save the report. Please try again.")
            false
        }
    }

    private fun showDownloadMessage(message: String) {
        runOnUiThread { Toast.makeText(this, message, Toast.LENGTH_LONG).show() }
    }

    inner class AndroidFileSaver {
        @JavascriptInterface
        fun saveFile(fileName: String, mimeType: String, base64Data: String): Boolean {
            val bytes = try {
                Base64.decode(base64Data, Base64.DEFAULT)
            } catch (_: IllegalArgumentException) {
                return false
            }
            return saveToDownloads(fileName, mimeType, bytes)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == FILE_CHOOSER_REQUEST) {
            val result = WebChromeClient.FileChooserParams.parseResult(resultCode, data)
            fileChooserCallback?.onReceiveValue(result)
            fileChooserCallback = null
        }
    }

    companion object {
        private const val FILE_CHOOSER_REQUEST = 1001

        private fun hideStatusBar(window: Window) {
            WindowCompat.setDecorFitsSystemWindows(window, true)
            WindowInsetsControllerCompat(window, window.decorView).hide(WindowInsetsCompat.Type.statusBars())
            window.setFlags(
                android.view.WindowManager.LayoutParams.FLAG_FULLSCREEN,
                android.view.WindowManager.LayoutParams.FLAG_FULLSCREEN
            )
        }
    }
}
