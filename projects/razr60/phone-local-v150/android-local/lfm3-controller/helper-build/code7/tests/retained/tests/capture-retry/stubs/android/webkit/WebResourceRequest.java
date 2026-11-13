package android.webkit; public interface WebResourceRequest { boolean isForMainFrame(); android.net.Uri getUrl(); String getMethod(); }
