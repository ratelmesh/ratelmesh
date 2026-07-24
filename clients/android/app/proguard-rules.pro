# gomobile's generated JNI entry points are discovered by name.
-keep class go.** { *; }
-keep class mobile.** { *; }
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# WireGuard's userspace backend contains JNI entry points as well.
-keep class com.wireguard.android.backend.** { *; }
