package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Immutable, finite action restrictions compiled only from the original task owner.
 * This is not a natural-language goal/effect/ordering verifier. It can remove
 * capabilities; it never grants a capability rejected by another dispatch gate.
 */
public final class OwnerActionPolicy {
    public static final String VERSION="hepta.owner-action-policy.v1";
    private static final List<String> ACTIONS=Collections.unmodifiableList(Arrays.asList(
            "find_app","open","click","type","scroll","back","home","wait","done"));
    private static final Map<String,String> ALIASES;
    static {
        LinkedHashMap<String,String> a=new LinkedHashMap<String,String>();
        for(String value:ACTIONS)a.put(value,value);
        a.put("查找","find_app");a.put("搜索","find_app");a.put("打开","open");a.put("结束","done");
        a.put("点击","click");a.put("输入","type");a.put("滚动","scroll");a.put("返回","back");
        a.put("回到桌面","home");a.put("等待","wait");a.put("tap","click");ALIASES=Collections.unmodifiableMap(a);
    }
    private static final String VERB="(?:查找|搜索|打开|结束|点击|输入|滚动|返回|回到桌面|等待|find_app|open|click|type|scroll|back|home|wait|done|tap)";
    private static final Pattern NEGATIVE=Pattern.compile("^(?:不要|禁止|不得|不许|勿|不|do\\s+not\\s+|don't\\s+|never\\s+|no\\s+)(.+)$");
    private static final Pattern ONLY=Pattern.compile("^(?:只允许|仅允许|只(?!读)|仅|only\\s+)(.+)$");
    private static final Pattern NEGATIVE_MENTION=Pattern.compile("(?:不要|禁止|不得|不许|勿|不|do\\s+not\\s+|don't\\s+|never\\s+|no\\s+)\\s*"+VERB);
    private static final Pattern ONLY_MENTION=Pattern.compile("(?:只允许|仅允许|只(?!读)|仅|only\\s+)\\s*"+VERB);
    private static final Pattern CONDITION=Pattern.compile("若|如果|当|一旦|假如|假设|除非|否则|只要|只有|直到|之后|之前|以后|除.{0,32}外|(?:进入|到达|打开).{0,40}后|\\b(?:if|when|unless|after|before|until)\\b");
    private static final Pattern LIST=Pattern.compile("、|以及|和|或|及|\\band\\b|\\bor\\b");
    public final String taskId,ownerSha256,policySha256;
    private final Set<String> allowed,denied;
    private final List<String> rules,unsupported,uncompiled;

    private OwnerActionPolicy(String task,String ownerSha,Set<String> allow,Set<String> deny,List<String> rule,List<String> bad,List<String> residual){
        taskId=task;ownerSha256=ownerSha;
        allowed=Collections.unmodifiableSet(new LinkedHashSet<String>(allow));
        denied=Collections.unmodifiableSet(new LinkedHashSet<String>(deny));
        rules=Collections.unmodifiableList(new ArrayList<String>(rule));
        unsupported=Collections.unmodifiableList(new ArrayList<String>(bad));
        uncompiled=Collections.unmodifiableList(new ArrayList<String>(residual));
        policySha256=sha((VERSION+"\n"+taskId+"\n"+ownerSha256+"\n"+join(allowed)+"\n"+join(denied)+"\n"+supported()).getBytes(StandardCharsets.UTF_8));
    }
    public static OwnerActionPolicy compile(String taskId,String originalOwner){
        if(taskId==null||!taskId.matches("[0-9a-f]{32}")||originalOwner==null||originalOwner.trim().isEmpty()
                ||originalOwner.getBytes(StandardCharsets.UTF_8).length>1600)
            throw new IllegalArgumentException("original task owner identity required");
        LinkedHashSet<String> allow=new LinkedHashSet<String>(ACTIONS),deny=new LinkedHashSet<String>();
        ArrayList<String> rule=new ArrayList<String>(),bad=new ArrayList<String>(),residual=new ArrayList<String>();
        String normalized=Normalizer.normalize(originalOwner,Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
        StringBuilder clean=new StringBuilder();
        for(int i=0;i<normalized.length();i++)if(Character.getType(normalized.charAt(i))!=Character.FORMAT)clean.append(normalized.charAt(i));
        String masked=maskQuotes(clean.toString(),bad);
        for(String sentence:masked.split("[。\\n.!?]+")){
            sentence=sentence.trim();if(sentence.isEmpty())continue;
            if(CONDITION.matcher(sentence).find()&&(NEGATIVE_MENTION.matcher(sentence).find()||ONLY_MENTION.matcher(sentence).find())){
                bad.add("conditional_action_constraint: "+sentence);continue;
            }
            for(String atom:sentence.split("[,;]+")){
                atom=atom.trim();if(atom.isEmpty())continue;
                Matcher negative=NEGATIVE.matcher(atom),only=ONLY.matcher(atom);
                Set<String> values=null;
                if(negative.matches()){
                    values=parseList(negative.group(1),true);
                    if(values!=null){deny.addAll(values);rule.add("deny:"+join(values));continue;}
                }else if(only.matches()){
                    values=parseList(only.group(1),false);
                    if(values!=null){allow.retainAll(values);rule.add("only:"+join(values));continue;}
                }
                if(NEGATIVE_MENTION.matcher(atom).find()||ONLY_MENTION.matcher(atom).find())bad.add("unsupported_action_constraint: "+atom);
                else residual.add(atom);
            }
        }
        allow.removeAll(deny);
        return new OwnerActionPolicy(taskId,sha(originalOwner.getBytes(StandardCharsets.UTF_8)),allow,deny,rule,bad,residual);
    }
    private static Set<String> parseList(String body,boolean parallelNegative){
        String[] pieces=LIST.split(body,-1);LinkedHashSet<String> result=new LinkedHashSet<String>();
        for(int i=0;i<pieces.length;i++){
            String value=pieces[i].trim();
            // The first prefix was already consumed. Stripping it twice would
            // silently turn a double negation into an authorization restriction.
            if(parallelNegative&&i>0){Matcher next=NEGATIVE.matcher(value);if(next.matches())value=next.group(1).trim();}
            String action=ALIASES.get(value);if(action==null)return null;result.add(action);
        }
        return result.isEmpty()?null:result;
    }
    private static String maskQuotes(String text,List<String> bad){
        StringBuilder out=new StringBuilder(text);char close=0;
        for(int i=0;i<text.length();i++){
            char c=text.charAt(i);
            if(close!=0){out.setCharAt(i,' ');if(c==close)close=0;continue;}
            if(c=='\''&&i>0&&i+1<text.length()&&Character.isLetterOrDigit(text.charAt(i-1))&&Character.isLetterOrDigit(text.charAt(i+1)))continue;
            if(c=='“')close='”';else if(c=='‘')close='’';else if(c=='「')close='」';else if(c=='『')close='』';else if(c=='"'||c=='\'')close=c;
            else if(c=='”'||c=='’'||c=='」'||c=='』'){bad.add("unmatched_quote");out.setCharAt(i,' ');}
            // Keep an opaque data token: quoted objects must not collapse a scoped
            // prohibition such as no-click(quoted target) into a global no-click.
            if(close!=0)out.setCharAt(i,'\ufffc');
        }
        if(close!=0)bad.add("unmatched_quote");return out.toString();
    }
    public boolean supported(){return unsupported.isEmpty();}
    public Set<String> allowedTypes(){return allowed;}
    public Set<String> deniedTypes(){return denied;}
    public List<String> uncompiledFragments(){return uncompiled;}
    public List<String> unsupportedConstraints(){return unsupported;}
    public void requireSupported(){
        if(!supported())throw new Violation("unsupported_owner_action_constraint","原指令包含暂不支持的动作权限表达，任务未执行；请使用独立、完整的动作限制句");
    }
    public void requireAllowed(String task,String action){
        if(!taskId.equals(task))throw new Violation("owner_lease_mismatch","原指令权限不属于本次任务，已停止操作");
        requireSupported();
        if(action==null||!allowed.contains(action))throw new Violation("owner_action_forbidden","原指令不允许此动作（"+action+"），本次未执行该动作，任务已停止；目标尚未确认");
    }
    public Map<String,Object> evidence(){
        LinkedHashMap<String,Object> result=new LinkedHashMap<String,Object>();
        result.put("schema",VERSION);result.put("task_id",taskId);result.put("original_instruction_sha256",ownerSha256);result.put("policy_sha256",policySha256);
        result.put("source","original_owner_instruction");result.put("status",supported()?"supported_action_constraints_only":"unsupported_action_constraint");
        result.put("allowed_action_types",new ArrayList<String>(allowed));result.put("denied_action_types",new ArrayList<String>(denied));
        result.put("compiled_rules",rules);result.put("unsupported_constraints",unsupported);result.put("uncompiled_fragments",uncompiled);
        result.put("complete_instruction_semantics_enforced",Boolean.FALSE);result.put("goal_effect_order_or_condition_verified",Boolean.FALSE);
        result.put("can_grant_other_guard_permission",Boolean.FALSE);return result;
    }
    public static final class Violation extends IllegalStateException {
        private static final long serialVersionUID=1L;
        public final String code;
        public Violation(String code,String message){super("owner_constraint_violation: "+message);this.code=code;}
    }
    private static String join(Iterable<String> values){StringBuilder s=new StringBuilder();for(String v:values){if(s.length()>0)s.append(',');s.append(v);}return s.toString();}
    private static String sha(byte[] value){
        try{byte[] digest=MessageDigest.getInstance("SHA-256").digest(value);StringBuilder s=new StringBuilder();for(byte b:digest)s.append(String.format(Locale.ROOT,"%02x",Integer.valueOf(b&255)));return s.toString();}
        catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException("SHA-256 unavailable",e);}
    }
}
