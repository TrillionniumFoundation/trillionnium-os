package org.trillionnium.hepta.webhelper;
/** Test-only fixed-site adapter: production policy is separately built from all actual source bytes. */
final class PageSitePolicy {
 String id="synthetic-fixed-mi";
 String origin(String raw){try{java.net.URI u=new java.net.URI(raw);return "https".equals(u.getScheme())&&"www.mi.com".equals(u.getHost())&&(u.getPort()==-1||u.getPort()==443)?"https://www.mi.com":null;}catch(Exception e){return null;}}
 boolean sameOrigin(String a,String b){String x=origin(a);return x!=null&&x.equals(origin(b));}
}
