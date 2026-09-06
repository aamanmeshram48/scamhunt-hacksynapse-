# ScamHunt Android Wrapper

This module packages the existing ScamHunt HTML/CSS/JavaScript application in a native Android WebView wrapper.

## Build

Requirements:

- JDK 17+
- Android SDK platform 34
- Android build-tools 34.0.0

From this directory:

```powershell
.\gradlew.bat assembleDebug
```

APK output:

```text
app\build\outputs\apk\debug\app-debug.apk
```

The wrapper loads `app/src/main/assets/index.html` and keeps the existing relative `css/`, `js/`, and `assets/` paths unchanged. `MainActivity` enables only JavaScript, DOM storage, local asset access, file selection, external URL handling, back navigation, and fullscreen status-bar hiding required by the existing app.
