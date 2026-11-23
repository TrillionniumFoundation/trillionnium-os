package org.trillionnium.hepta.webprotocol;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;
import org.json.*;
/** Original canonical strings are the unchanged oracle, including exception class/message and bounds. */
public final class CanonicalComparisonParity {
    static int cases,assertions;
    static void check(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    static String result(Object a,Object b,boolean original){
        try{return "value:"+(original?WebDomCanonical.canonical(a).equals(WebDomCanonical.canonical(b)):WebDomCanonical.same(a,b));}
        catch(Exception e){return "error:"+e.getClass().getName()+":"+e.getMessage();}
    }
    static void parity(String name,Object a,Object b){String x=result(a,b,true),y=result(a,b,false);check(x.equals(y),name+" parity differs: "+x+" / "+y);cases++;}
    static String repeated(char c,int n){char[] chars=new char[n];Arrays.fill(chars,c);return new String(chars);}
    static Object random(Random r,int depth)throws Exception{
        int choice=r.nextInt(depth==0?5:7);
        if(choice==0)return r.nextBoolean()?null:JSONObject.NULL;
        if(choice==1)return r.nextBoolean();
        if(choice==2)return new String[]{"","a","\u0000\n\r\t","\\\"","中文😀","null","0"}[r.nextInt(7)];
        if(choice==3)return new Number[]{Integer.valueOf(0),Double.valueOf(-0.0),Long.valueOf(9007199254740991L),Double.valueOf(Double.MIN_VALUE),new BigDecimal("1.0000"),new BigInteger("12"),Float.valueOf(0.1f)}[r.nextInt(7)];
        if(choice==4)return Integer.valueOf(r.nextInt(100));
        if(choice==5){JSONArray a=new JSONArray();for(int i=0,n=r.nextInt(5);i<n;i++)a.put(random(r,depth-1));return a;}
        JSONObject o=new JSONObject();for(int i=0,n=r.nextInt(5);i<n;i++)o.put("k"+i,random(r,depth-1));return o;
    }
    static final class CountedNumber extends Number {
        private static final long serialVersionUID=1L;int calls;
        @Override public int intValue(){return 1;}@Override public long longValue(){return 1;}
        @Override public float floatValue(){return 1;}@Override public double doubleValue(){if(++calls!=1)throw new IllegalStateException("number read twice");return 1;}
    }
    public static void main(String[] args)throws Exception{
        Object[] values={null,JSONObject.NULL,true,false,"null","0","{}","[]",0,-0.0,1,1.0,new BigDecimal("1.0000"),Double.MIN_VALUE,9007199254740991L,"中文😀\u0000\\\"",new JSONArray(),new JSONObject()};
        for(Object a:values)for(Object b:values)parity("scalar-cross-product",a,b);
        parity("object-key-order",new JSONObject().put("z",1).put("a",2),new JSONObject().put("a",2).put("z",1));
        parity("array-order",new JSONArray().put("a").put("b"),new JSONArray().put("b").put("a"));
        parity("nested-structure",new JSONObject().put("a",new JSONArray().put(1).put("2")),new JSONObject().put("a",new JSONArray().put("1").put(2)));
        for(Object bad:new Object[]{Double.NaN,Double.POSITIVE_INFINITY,Double.NEGATIVE_INFINITY,9007199254740992L,"\uD800","\uDC00",new Object(),repeated('a',1048577)}){
            parity("invalid-left",bad,0);parity("invalid-right",0,bad);
        }
        parity("invalid-late-left-after-mismatch",new JSONObject().put("a",1).put("z","\uD800"),new JSONObject().put("a",2));
        parity("invalid-late-right-after-mismatch",new JSONObject().put("a",1),new JSONObject().put("a",2).put("z","\uDC00"));
        parity("invalid-key",new JSONObject().put("\uD800",1),new JSONObject());
        parity("long-key",new JSONObject().put(repeated('k',1048577),1),new JSONObject());
        Object nested=0;for(int i=0;i<64;i++)nested=new JSONArray().put(nested);parity("max-depth",nested,nested);
        nested=new JSONArray().put(nested);parity("excess-depth",nested,nested);
        JSONObject object=new JSONObject();for(int i=0;i<4096;i++)object.put("k"+i,1);parity("max-object",object,object);object.put("extra",1);parity("excess-object",object,0);
        JSONArray count=new JSONArray();for(int i=0;i<179999;i++)count.put(0);parity("max-values",count,count);count.put(0);parity("excess-values",count,0);count.put(0);parity("excess-array",count,0);
        parity("max-string",repeated('a',1048576),repeated('a',1048576));
        parity("escaped-output-over-limit",repeated('\u0001',699051),0);
        JSONArray exact=new JSONArray().put(repeated('a',1048576)).put(repeated('b',1048576)).put(repeated('c',1048576)).put(repeated('d',1048563));
        parity("completed-output-exact-limit",exact,exact);
        exact.put(3,repeated('d',1048564));parity("completed-output-over-limit",exact,0);
        exact.put(0,repeated('\u0001',1048576));parity("intermediate-output-over-limit",exact,0);
        Random random=new Random(472132L);for(int i=0;i<600;i++){Object a=random(random,5),b=random(random,5);parity("seeded-pair",a,b);parity("seeded-reflexive",a,a);}
        CountedNumber a=new CountedNumber(),b=new CountedNumber();check(WebDomCanonical.same(a,b)&&a.calls==1&&b.calls==1,"number conversion repeated");cases++;
        System.out.println(new JSONObject().put("schema","hepta.canonical-comparison-parity.v1").put("all_pass",true).put("cases",cases).put("assertions",assertions).put("oracle","unchanged canonical(left).equals(canonical(right))").put("phone_operations",0));
    }
}
