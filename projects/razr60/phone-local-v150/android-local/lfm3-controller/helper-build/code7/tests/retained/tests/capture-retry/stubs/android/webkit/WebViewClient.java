package android.webkit;
public class WebViewClient {
 public void onPageStarted(WebView v,String u,android.graphics.Bitmap b){}
 public void onPageCommitVisible(WebView v,String u){}
 public void doUpdateVisitedHistory(WebView v,String u,boolean r){}
 public void onPageFinished(WebView v,String u){}
 public void onScaleChanged(WebView v,float o,float n){}
 public void onReceivedError(WebView v,WebResourceRequest r,WebResourceError e){}
 public void onReceivedSslError(WebView v,SslErrorHandler h,android.net.http.SslError e){}
 public boolean shouldOverrideUrlLoading(WebView v,WebResourceRequest r){return false;}
}
