package net.gotev.cookiestore

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.net.HttpCookie
import java.net.URI

open class EncryptedSharedPreferencesCookiesStore(
    context: Context,
    private val name: String
) : InMemoryCookieStore(name) {

    private val preferences = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            context,
            name,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    } else {
        context.getSharedPreferences(name, Context.MODE_PRIVATE)
    }

    private val gson = Gson()

    init {
        synchronized(EncryptedSharedPreferencesCookiesStore::class.java) {
            preferences.all.forEach { (key, value) ->
                try {
                    val index = URI.create(key)
                    val listType = object : TypeToken<MutableList<InternalCookie>>() {}.type
                    val internalCookies =
                        gson.fromJson<MutableList<InternalCookie>>(value.toString(), listType)
                    val cookies = internalCookies.map { it.toHttpCookie() }.toMutableList()
                    uriIndex[index] = cookies
                } catch (exception: Throwable) {
                    Log.e(
                        javaClass.simpleName,
                        "Error while loading key = $key, value = $value from cookie store named $name",
                        exception
                    )
                }
            }
        }
    }

    override fun removeAll(): Boolean =
        synchronized(EncryptedSharedPreferencesCookiesStore::class.java) {
            super.removeAll()
            preferences.edit().clear().apply()
            true
        }

    override fun add(uri: URI?, cookie: HttpCookie?) =
        synchronized(EncryptedSharedPreferencesCookiesStore::class.java) {
            uri ?: return@synchronized

            super.add(uri, cookie)
            val index = getEffectiveURI(uri)
            val cookies = uriIndex[index] ?: return@synchronized

            val internalCookies = cookies.map {
                InternalCookie(it).apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        httpOnly = it.isHttpOnly
                    }
                }
            }

            val listType = object : TypeToken<MutableList<InternalCookie>>() {}.type
            val json = gson.toJson(internalCookies, listType)

            preferences
                .edit()
                .putString(index.toString(), json)
                .apply()
        }

    override fun remove(uri: URI?, cookie: HttpCookie?): Boolean =
        synchronized(EncryptedSharedPreferencesCookiesStore::class.java) {
            uri ?: return false

            val result = super.remove(uri, cookie)
            val index = getEffectiveURI(uri)
            val cookies = uriIndex[index]
            val internalCookies = cookies?.map {
                InternalCookie(it).apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        httpOnly = it.isHttpOnly
                    }
                }
            }
            val listType = object : TypeToken<MutableList<InternalCookie>>() {}.type
            val json = gson.toJson(internalCookies, listType)

            preferences.edit().apply {
                when (cookies) {
                    null -> remove(index.toString())
                    else -> putString(index.toString(), json)
                }
            }.apply()

            return result
        }
}
