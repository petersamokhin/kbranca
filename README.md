# Branca
Branca is a secure alternative to JWT, This implementation is written in Kotlin and implements the [branca token specification](https://github.com/tuupola/branca-spec).

Original Java implementation: [jbranca](https://github.com/bjoernw/jbranca)

### Install
- Add `jitpack.io` to your repositories list
```
repositories {
    // ...
    maven { url 'https://jitpack.io' }
}
```
- Add library to dependencies list
```
dependencies {
    implementation "com.github.petersamokhin:kbranca:$kbrancaVersion"
}
```

Latest version: https://github.com/petersamokhin/kbranca/releases/latest

# Example

```kotlin
val key = "SecretKeyYouShouldNeverCommit!!!" // exactly 32 chars

val factory = BrancaTokenFactory(key)
val plaintext = """{"key": "example_value"}"""
val encoded = factory.encode(plaintext.toByteArray())
val decoded = factory.decode(encoded)
assertEquals(plaintext, String(decoded))
```

### 3rd party
- [Bouncycastle](https://www.bouncycastle.org/java.html)
- [seruco/base62](https://github.com/seruco/base62)