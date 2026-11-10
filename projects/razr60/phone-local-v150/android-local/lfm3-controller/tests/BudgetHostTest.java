import org.trillionnium.hepta.local.ConservativeTokenBudget;
public final class BudgetHostTest {
    private static int assertions;
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    private static String repeated(char c,int n){char[] value=new char[n];java.util.Arrays.fill(value,c);return new String(value);}
    public static void main(String[] ignored)throws Exception{
        check(ConservativeTokenBudget.bytesUpper("abc")==3,"ASCII bytes");
        check(ConservativeTokenBudget.bytesUpper("中文")==6,"CJK bytes");
        check(ConservativeTokenBudget.bytesUpper("e\u0301")==3,"raw decomposed bytes");
        check(ConservativeTokenBudget.bytesUpper("\u0344")==2,"no normalization is applied for pinned LFM3");
        check(ConservativeTokenBudget.bytesUpper("\ud83d\ude00")==4,"standard UTF-8 emoji not modified UTF-8");
        for(int context:new int[]{4096,8192}){
            int textLimit=2*(context-256-256-512-2);
            ConservativeTokenBudget projected=ConservativeTokenBudget.estimate("sys",repeated('a',textLimit-3),context);
            check(projected.totalContextUpper==context&&projected.admitted,"diagnostic projection boundary");
            check(!projected.provenUpperBound&&projected.mayAttemptNative(),"LFM3 requires native exact admission");
            ConservativeTokenBudget over=ConservativeTokenBudget.estimate("sys",repeated('a',textLimit-2),context);
            check(!over.admitted&&over.mayAttemptNative(),"projection overflow cannot bypass or preempt native count");
            check(!ConservativeTokenBudget.estimate("sys",repeated('中',textLimit),context).admitted,"multibyte cannot use char count");
        }
        check(ConservativeTokenBudget.estimate("system","<|im_start|>user\n中文<think></think>",4096).admitted,"literal template bytes are counted");
        for(String s:new String[]{"\ud800","\udc00","x\u0000y","\ud800x"}){
            boolean rejected=false;try{ConservativeTokenBudget.bytesUpper(s);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"invalid Unicode/NUL rejected");
        }
        System.out.println("PASS "+assertions+" UTF-8 and advisory-projection assertions; native_tokenization_not_run=true; phone_tested=false");
    }
}
