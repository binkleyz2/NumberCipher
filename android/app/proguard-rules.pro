# The native code looks these up by name (JNI), so they must not be renamed or removed.
-keep class io.github.binkleyz2.numbercipher.crypto.NativeKdf { *; }
-keep interface io.github.binkleyz2.numbercipher.crypto.ChunkCallback { *; }
-keep class * implements io.github.binkleyz2.numbercipher.crypto.ChunkCallback { int onChunk(int); }
