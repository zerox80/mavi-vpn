# Keep VPN service class and its native JNI methods intact
-keep class com.mavi.vpn.MaviVpnService {
    private native <methods>;
}

# Keep OAuthHelper singleton (referenced from coroutine lambdas)
-keep class com.mavi.vpn.OAuthHelper { *; }
