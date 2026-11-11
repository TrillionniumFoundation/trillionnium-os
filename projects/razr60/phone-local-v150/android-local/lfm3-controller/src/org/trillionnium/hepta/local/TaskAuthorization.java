package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A bounded OWNER compiler and task-local executor contract, never a model proposal.
 * This enforces documented tool/method clauses, not arbitrary business semantics. */
public final class TaskAuthorization {
    public static final String SCHEMA="hepta.owner-task-authorization.v1";
    public static final String PARSER="hepta.owner-tool-clauses.zh.v4-fixed-intents";
    public static final Set<String> TOOLS=Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(
            "find_app","open","click","type","submit","scroll","back","home","wait","done","notes.create","web.search")));
    public static final class Violation extends IllegalStateException {
        private static final long serialVersionUID=1L;
        Violation(String message){super("task_authorization: "+message);}
    }
    static void require(boolean value,String message){if(!value)throw new Violation(message);}
    private static final Map<String,String> NAMES;
    static {
        Map<String,String> names=new LinkedHashMap<String,String>();
        String[][] rows={{"find_app","查找本机应用","查找应用","查找","find_app"},
                {"open","打开应用","打开","open"},{"click","点击","click"},{"type","输入","type"},
                {"submit","提交输入","提交","submit"},
                {"notes.create","创建笔记","新建笔记","写备忘录","notes.create"},
                {"web.search","网页搜索","网页查询","web.search"},
                {"scroll","滚动","scroll"},{"back","返回上一页","返回","back"},
                {"home","回到桌面","返回桌面","home"},{"wait","等待","wait"},
                {"done","结束任务","结束","done"}};
        for(String[] row:rows)for(int i=1;i<row.length;i++)names.put(row[i],row[0]);
        NAMES=Collections.unmodifiableMap(names);
    }
    private static final Pattern ONLY=Pattern.compile("^(?:请)?(?:本任务|这次任务)?(?:只|仅)(?:允许|可|能)?(?:使用|调用|执行)?(.+)$");
    private static final Pattern DENY=Pattern.compile("^(?:请)?(?:不要|不得|禁止|不允许|不能|不)(?:直接|自动|再次|随意)?(.+)$");
    private static final Pattern GRANT=Pattern.compile("^(?:但|但是)?(?:可以|允许)(.+)$");
    private static final Pattern EXCEPTION=Pattern.compile("(?:除非|除了|否则|但是|但可以|但允许|不过|如果|若|而是)");
    private static final Pattern SEQUENCE=Pattern.compile("先([^。；;\\n]*?)(?:再|然后)([^。；;\\n]*)");
    private static final Pattern QUOTED_QUERY=Pattern.compile("(?:搜索|查找)\\s*[‘“\"']([^‘’“”\"'\\r\\n]{1,64})[’”\"']");
    private static final Pattern NAMED_QUERY=Pattern.compile("(?:查找|搜索)(?:手机上|本机|手机中)?(?:已安装的|安装的)?([^，,。；;\\n]{1,64}?)(?:应用|APP|App)?[，,\\s]*$");
    // An app-discovery prerequisite needs an explicit application/tool domain.
    // "查找机票/商品，再打开详情" describes app content, not installed apps.
    // This pattern only sees quote-masked text; quoted payload is never authority.
    private static final Pattern APP_LOOKUP=Pattern.compile(
            "(?<![A-Za-z0-9_])find_app(?![A-Za-z0-9_])"
            +"|(?:查找|搜索)(?:手机上|本机|手机中)?(?:已安装的|安装的)"
            +"|(?:查找|搜索)[^，,。；;\\n]{0,96}?(?:应用|APP|App)(?=[，,。；;\\s]|$|并|再|然后)");
    public final String instructionSha256,sha256,findQuery;
    private final String parserVersion;
    public final Set<String> allowedTools;
    public final boolean requireFindAppBeforeOpen;
    private final List<String> rules;
    private final String immutableOwner;

    private TaskAuthorization(String owner,Set<String> allowed,boolean first,String query,List<String> rules){
        immutableOwner=owner;
        instructionSha256=hash(owner.getBytes(StandardCharsets.UTF_8));
        allowedTools=Collections.unmodifiableSet(new TreeSet<String>(allowed));
        requireFindAppBeforeOpen=first;findQuery=query;
        this.rules=Collections.unmodifiableList(new ArrayList<String>(rules));
        parserVersion=rules.contains("notes_literal_owner_span.v1")?PARSER+"+notes-literal-span.v1":PARSER;
        // Length-delimited fields bind exact UTF-8, including the optional query.
        StringBuilder identity=new StringBuilder();field(identity,SCHEMA);field(identity,parserVersion);field(identity,instructionSha256);
        for(String tool:allowedTools)field(identity,tool);field(identity,first?"true":"false");field(identity,query==null?"":query);
        sha256=hash(identity.toString().getBytes(StandardCharsets.UTF_8));
    }
    /** The service compiles its task phase from the same OWNER; never model or screen text. */
    String immutableOwner(){return immutableOwner;}
    public static TaskAuthorization parse(String owner){
        validOwner(owner);
        NotesOwnerIntent.Result note=NotesOwnerIntent.parse(owner);
        String unquoted=withoutQuotedData(note.supported?note.maskedOwnerForAuthority(owner):owner);
        Set<String> allowed=new TreeSet<String>(TOOLS),denied=new TreeSet<String>(),granted=new TreeSet<String>();
        List<String> rules=new ArrayList<String>();boolean onlySeen=false;
        if(note.supported)rules.add("notes_literal_owner_span.v1");
        for(String original:unquoted.split("[，,。；;！!？?\\r\\n]")){
            String clause=original.trim();if(clause.isEmpty())continue;
            Matcher only=ONLY.matcher(clause),deny=DENY.matcher(clause),grant=GRANT.matcher(clause);
            if(only.matches()&&(startsTool(only.group(1))||clause.matches("^(?:请)?(?:本任务|这次任务)?(?:只|仅)(?:允许|可|能).*$"))){
                require(!EXCEPTION.matcher(clause).find(),"工具白名单含不支持的条件或例外");
                Set<String> listed=toolList(only.group(1),true);
                if(onlySeen)allowed.retainAll(listed);else{allowed.clear();allowed.addAll(listed);onlySeen=true;}
                rules.add("only_tools");
            }else if(deny.matches()){
                String body=deny.group(1).trim();
                if(startsNegation(body)&&containsTool(body))throw new Violation("工具限制含双重否定，不能推断授权");
                if(startsTool(body)){
                    require(!EXCEPTION.matcher(clause).find(),"工具禁止条款含不支持的条件或例外");
                    denied.addAll(toolList(body,false));rules.add("deny_tools");
                }
            }else if(grant.matches()&&startsTool(grant.group(1))){
                granted.addAll(toolList(grant.group(1),false));
            }
            // A limited explicit method clause. It forbids SET_TEXT, not key clicks.
            if(clause.matches(".*(?:使用|通过)[^。；;]{0,40}(?:按键|逐个按键|按按钮)(?:输入|计算|操作|完成).*$")){
                denied.add("type");rules.add("observed_keys_no_type");
            }
        }
        for(String tool:denied)require(!granted.contains(tool),"工具允许与禁止冲突");
        if(onlySeen)for(String tool:granted)require(allowed.contains(tool),"工具白名单后出现扩大授权的条款");
        allowed.removeAll(denied);
        boolean first=false;String query=null;
        // Masking preserves UTF-16 offsets. Recognize the method in unquoted
        // text, then recover its literal query from the same original span.
        Matcher sequence=SEQUENCE.matcher(unquoted);
        while(sequence.find()){
            String before=sequence.group(1),after=sequence.group(2);
            if(explicitAppLookup(before)&&(after.contains("打开")||after.contains("open"))){
                require(!first,"多个查找前置目标暂不支持");
                require(!EXCEPTION.matcher(before).find(),"查找前置条件有歧义");
                query=queryFrom(owner.substring(sequence.start(1),sequence.end(1)));first=true;rules.add("find_app_before_open");
            }
        }
        if(!first&&unquoted.contains("先")&&explicitAppLookup(unquoted)
                &&(unquoted.contains("打开")||unquoted.contains("open")))
            throw new Violation("查找与打开顺序不在已支持的明确先后语法内");
        if(first)require(allowed.contains("find_app")&&allowed.contains("open"),"查找前置与工具限制冲突");
        return new TaskAuthorization(owner,allowed,first,query,rules);
    }
    private static boolean explicitAppLookup(String text){return APP_LOOKUP.matcher(text.trim()).find();}
    private static String queryFrom(String before){
        Matcher quoted=QUOTED_QUERY.matcher(before);String query=null;
        if(quoted.find()){query=quoted.group(1);require(!quoted.find(),"查找前置含多个文字目标");}
        if(query==null){Matcher named=NAMED_QUERY.matcher(before);if(named.find())query=named.group(1).trim();}
        require(query!=null&&!query.isEmpty(),"查找前置需要明确的应用名称或搜索文字");
        require(!query.matches(".*(?:工具|find_app|先|再|然后|允许|禁止|不要|不得|或|或者|以及|和).*$"),"查找目标不在已支持的单一文字范围");
        AppCatalogueRanker.validateQuery(query);
        return query;
    }
    private static boolean startsNegation(String value){return value.startsWith("不")||value.startsWith("禁止")||value.startsWith("不得");}
    private static boolean containsTool(String value){for(String name:NAMES.keySet())if(value.contains(name))return true;return false;}
    private static boolean startsTool(String value){return toolPrefix(value.trim())!=null;}
    private static String toolPrefix(String value){
        String best=null;for(String name:NAMES.keySet())if(value.startsWith(name)&&(best==null||name.length()>best.length()))best=name;
        return best;
    }
    private static Set<String> toolList(String text,boolean exact){
        Set<String> result=new TreeSet<String>();
        for(String item:text.trim().split("(?:、|和|及|与|或)")){
            String value=item.trim();
            if(!exact){Matcher repeated=DENY.matcher(value);if(repeated.matches()){
                value=repeated.group(1).trim();require(!startsNegation(value),"工具列表含双重否定");
            }}
            String prefix=toolPrefix(value);
            require(prefix!=null,"工具列表包含未知项目");
            String suffix=value.substring(prefix.length()).trim();
            if(exact)require(suffix.isEmpty()||suffix.equals("工具")||suffix.equals("操作"),"只允许列表必须是完整工具名，不支持隐含例外或参数");
            else require(!startsNegation(suffix)&&!EXCEPTION.matcher(suffix).find(),"工具禁止条款尾部有歧义");
            result.add(NAMES.get(prefix));
        }
        require(!result.isEmpty(),"工具列表为空");return result;
    }
    private static String withoutQuotedData(String owner){
        StringBuilder out=new StringBuilder(owner);char close=0;int begin=-1;
        for(int i=0;i<owner.length();i++){
            char c=owner.charAt(i);
            if(close==0){
                if(c=='“'||c=='‘'||c=='\"'||c=='\''){close=c=='“'?'”':c=='‘'?'’':c;begin=i;out.setCharAt(i,' ');}
            }else{
                out.setCharAt(i,' ');
                if(c==close){
                    String quoted=owner.substring(begin+1,i);
                    require(!(containsTool(quoted)&&(quoted.contains("不")||quoted.contains("禁止")||quoted.contains("只允许")||quoted.contains("仅允许"))),"引用文字内含工具限制，无法确定是数据还是授权");
                    close=0;
                }
            }
        }
        require(close==0,"任务中的引号未闭合");return out.toString();
    }
    private static void validOwner(String owner){
        require(owner!=null&&!owner.trim().isEmpty(),"用户任务不能为空");
        require(owner.indexOf('\0')<0&&!owner.contains("<|")&&!owner.contains("<__image__>")&&owner.getBytes(StandardCharsets.UTF_8).length<=1600,"用户任务太长或包含不支持的字符");
        for(int i=0;i<owner.length();i++){
            char c=owner.charAt(i);
            if(Character.isHighSurrogate(c))require(i+1<owner.length()&&Character.isLowSurrogate(owner.charAt(++i)),"用户任务含无效字符");
            else require(!Character.isLowSurrogate(c),"用户任务含无效字符");
        }
    }
    public boolean allows(String tool){return allowedTools.contains(tool);}
    public void requireOwner(String owner){validOwner(owner);require(instructionSha256.equals(hash(owner.getBytes(StandardCharsets.UTF_8))),"用户任务与授权合同不一致");}
    public Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);out.put("parser",parserVersion);
        out.put("instruction_sha256",instructionSha256);out.put("authorization_sha256",sha256);
        out.put("allowed_tools",new ArrayList<String>(allowedTools));out.put("require_find_app_before_open",requireFindAppBeforeOpen);
        out.put("find_query",findQuery);out.put("recognized_rules",new ArrayList<String>(rules));
        out.put("arbitrary_semantic_constraints_verified",false);return out;
    }
    public String summary(){
        Map<String,String> display=new LinkedHashMap<String,String>();
        display.put("find_app","查找应用");display.put("open","打开应用");display.put("click","点击");display.put("type","输入文字");
        display.put("submit","提交已观察查询字段");
        display.put("notes.create","打开本地笔记草稿");display.put("web.search","打开网页查询");
        display.put("scroll","滚动");display.put("back","返回");display.put("home","回桌面");display.put("wait","等待");display.put("done","成功结束");
        List<String> names=new ArrayList<String>();for(String tool:display.keySet())if(allowedTools.contains(tool))names.add(display.get(tool));
        return "已识别的工具权限："+names+(requireFindAppBeforeOpen?"；须先查找“"+findQuery+"”并打开真实结果才能成功结束":"")
                +"。可随时停止或报告未完成；页面目标和其它语义条件仍需核对。";
    }
    public Gate bind(String taskId){return new Gate(this,taskId);}
    private static void field(StringBuilder out,String value){out.append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value).append('\n');}
    private static String hash(byte[] value){
        try{StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(value))out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();}
        catch(Exception impossible){throw new IllegalStateException(impossible);}
    }

    /** Immutable grammar/policy view. Its contract can only be narrowed by task evidence. */
    public static final class Frame {
        public final TaskAuthorization authorization;
        public final String taskId,discoveryRunId,openedPackage;
        public final Set<String> foundPackages;
        private Frame(Gate gate){authorization=gate.authorization;taskId=gate.taskId;discoveryRunId=gate.discoveryRunId;
            openedPackage=gate.openedPackage;foundPackages=Collections.unmodifiableSet(new TreeSet<String>(gate.foundPackages));}
        public boolean allows(String tool){
            if("done".equals(tool))return true; // partial/failure are always safe termination controls.
            if(!authorization.allows(tool))return false;
            return !authorization.requireFindAppBeforeOpen||openedPackage!=null||"find_app".equals(tool)||"open".equals(tool)||"wait".equals(tool);
        }
        public boolean successAllowed(){return authorization.allows("done")&&(!authorization.requireFindAppBeforeOpen||openedPackage!=null);}
        public Set<String> openPackages(Set<String> projected){
            Set<String> out=new TreeSet<String>(projected);
            if(!allows("open"))out.clear();else if(authorization.requireFindAppBeforeOpen)out.retainAll(foundPackages);
            return out;
        }
        public void requireDecision(ActionDecision action){
            require(action!=null,"动作缺失");
            if("done".equals(action.action)){require(!"success".equals(action.status)||successAllowed(),"尚未满足用户要求的方法，不允许成功结束");return;}
            require(allows(action.action),"用户未授权此工具或前置查找/打开未完成："+action.action);
            if("find_app".equals(action.action)&&authorization.requireFindAppBeforeOpen)
                require(authorization.findQuery.equals(action.query),"查找文字必须等于用户指定的文字");
            if("open".equals(action.action)&&authorization.requireFindAppBeforeOpen)
                require(discoveryRunId!=null&&foundPackages.contains(action.packageName),"打开目标没有同任务真实查找证明");
        }
        public Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>(authorization.evidence());out.put("task_id",taskId);
            out.put("discovery_run_id",discoveryRunId);out.put("found_packages",new ArrayList<String>(foundPackages));
            out.put("opened_package",openedPackage);out.put("success_done_allowed",successAllowed());return out;
        }
    }
    /** Service-owned state. Only actual local catalogue reads and dispatched opens advance it. */
    public static final class Gate {
        public final TaskAuthorization authorization;public final String taskId;
        private final Set<String> foundPackages=new TreeSet<String>();
        private boolean retired;private String refusal,catalogueSha,discoveryRunId,discoveryObservationId;
        private String openRunId,pendingOpen,openedPackage,openedObservationId;
        private Map<String,Object> lastCheck=Collections.emptyMap();
        private Gate(TaskAuthorization authorization,String taskId){require(authorization!=null&&taskId!=null&&taskId.matches("[0-9a-f]{32}"),"任务授权绑定无效");this.authorization=authorization;this.taskId=taskId;}
        public synchronized Frame frame(){ready();return new Frame(this);}
        public synchronized void ready(){require(!retired,"任务授权已退休");require(refusal==null,refusal==null?"":refusal);}
        public synchronized void retire(){retired=true;}
        public synchronized void bindCatalogue(AppCatalogueRanker.Page page){
            ready();require(page!=null&&catalogueSha==null,"初始应用目录缺失或重复");catalogueSha=page.catalogueSha256;
            // Initial projection is deliberately not a successful model-issued lookup.
        }
        public synchronized void check(ActionDecision action,String modelRunId){
            Map<String,Object> proof=new LinkedHashMap<String,Object>();proof.put("schema","hepta.owner-action-check.v1");
            proof.put("task_id",taskId);proof.put("authorization_sha256",authorization.sha256);proof.put("model_run_id",modelRunId);
            proof.put("action",action==null?null:action.action);proof.put("target_package",action==null?null:action.packageName);
            if(action!=null&&action.toolChildOrigin!=null){proof.put("actor_kind","tool_child");proof.put("model_issued",false);
                proof.put("parent_model_run_id",modelRunId);}
            try{ready();require(modelRunId!=null&&modelRunId.matches("[0-9a-f]{32}"),"模型运行身份缺失");new Frame(this).requireDecision(action);proof.put("allowed",true);}
            catch(Violation error){refusal=error.getMessage();proof.put("allowed",false);proof.put("reason",refusal);throw error;}
            finally{lastCheck=Collections.unmodifiableMap(proof);}
        }
        synchronized void found(ActionDecision action,String modelRunId,AppCatalogueRanker.Page page){
            check(action,modelRunId);
            require("find_app".equals(action.action)&&page!=null&&catalogueSha!=null&&catalogueSha.equals(page.catalogueSha256)
                    &&action.query.equals(page.query)&&action.offset==page.offset,"实际查找回执不属于本次目录/查询");
            foundPackages.clear();for(AppCatalogueRanker.Entry app:page.apps)foundPackages.add(app.packageName);
            discoveryRunId=modelRunId;discoveryObservationId=action.observationId;
        }
        synchronized void opened(ActionDecision action,String modelRunId){
            check(action,modelRunId);require("open".equals(action.action),"非打开动作不能授予打开证明");
            pendingOpen=action.packageName;openRunId=modelRunId;
        }
        synchronized void observed(String packageName,String observationId){
            ready();require(observationId!=null&&observationId.matches("[0-9a-f]{32}"),"观察身份缺失");
            if(pendingOpen!=null&&pendingOpen.equals(packageName)){openedPackage=pendingOpen;openedObservationId=observationId;pendingOpen=null;}
        }
        public synchronized Map<String,Object> evidence(){
            Map<String,Object> out=new Frame(this).evidence();out.put("catalogue_sha256",catalogueSha);
            out.put("discovery_observation_id",discoveryObservationId);out.put("open_run_id",openRunId);
            out.put("opened_observation_id",openedObservationId);out.put("pending_open_package",pendingOpen);
            out.put("retired",retired);out.put("refused",refusal!=null);out.put("refusal",refusal);
            out.put("last_check",new LinkedHashMap<String,Object>(lastCheck));return out;
        }
    }
}
