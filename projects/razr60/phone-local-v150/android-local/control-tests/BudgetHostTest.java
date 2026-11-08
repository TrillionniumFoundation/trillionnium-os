import org.trillionnium.hepta.localprobe.ConservativeTokenBudget;
public final class BudgetHostTest {
    private static int assertions;
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    private static String repeated(char c,int n){char[] value=new char[n];java.util.Arrays.fill(value,c);return new String(value);}
    public static void main(String[] ignored)throws Exception{
        check(ConservativeTokenBudget.bytesUpper("abc")==3,"ASCII bytes");
        check(ConservativeTokenBudget.bytesUpper("中文")==6,"CJK bytes");
        check(ConservativeTokenBudget.bytesUpper("e\u0301")==3,"decomposed raw must not shrink");
        check(ConservativeTokenBudget.bytesUpper("\u0344")==4,"NFC expansion must be included");
        check(ConservativeTokenBudget.bytesUpper("\ud83d\ude00")==4,"emoji bytes");
        int textLimit=4096-256-256-192-256-2-1;
        ConservativeTokenBudget exact=ConservativeTokenBudget.estimate("sys",repeated('a',textLimit-3));
        check(exact.totalContextUpper==4096&&exact.admitted,"exact boundary");
        check(!ConservativeTokenBudget.estimate("sys",repeated('a',textLimit-2)).admitted,"one-byte overflow");
        check(!ConservativeTokenBudget.estimate("sys",repeated('中',textLimit)).admitted,"multibyte cannot use char count");
        for(String s:new String[]{"<__image__>","data <__image__> more"}){
            boolean rejected=false;try{ConservativeTokenBudget.estimate("sys",s);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"reserved marker rejected");
        }
        java.io.File wrong=java.io.File.createTempFile("hepta-tokenizer-fixture-",".json");
        try(java.io.FileOutputStream stream=new java.io.FileOutputStream(wrong)){stream.write("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));}
        boolean rejected=false;try{ConservativeTokenBudget.verifyTokenizer(wrong);}catch(IllegalArgumentException expected){rejected=true;}finally{wrong.delete();}
        check(rejected,"foreign tokenizer cannot authorize byte bound");
        System.out.println("PASS "+assertions+" conservative-budget assertions; exact_token_count=false");
    }
}
