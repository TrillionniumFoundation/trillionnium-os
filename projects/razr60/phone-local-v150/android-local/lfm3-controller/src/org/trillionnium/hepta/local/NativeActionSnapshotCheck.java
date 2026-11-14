package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.util.*;
import java.util.regex.*;

/** Pure candidate predicate, NOT a dispatch permit or a PhoneObservation.
 * No Session mutation, screenshot claim, query history, I/O, effect or retry.
 * Runtime must separately bind the original Session Attempt/Domain/NodeRef,
 * actual parent-child identities, current windows/IME, and one effect entry.
 * Query requires the real already-reserved Attempt and calendar-year history;
 * a matching snapshot alone cannot supply either. */
final class NativeActionSnapshotCheck {
    static final int MAX_NODES=1536, MAX_TEXT=32768, MAX_BYTES=1048576;
    static final String CTRIP="ctrip.android.view", XIAOMI="com.xiaomi.shop";
    static final String OPEN="open_flight_form", YEAR="inspect_departure_year", QUERY="query_observed_form", SEARCH="open_search";
    static final String CP=CTRIP+":id/";
    static final Set<String> NK=keys("path,parent_class,package,window_id,class,view_id,text,description,label,ref_signature_sha256,bounds,visible,enabled,clickable,editable,scrollable,focused,password,selected,checkable,checked,children,scroll_actions,ime_enter,input_sha256,action_click");
    static final Set<String> EK=keys("task_id,owner_sha256,target_sha256,authorization_sha256,selection_sha256,installed_set_sha256,goal_sha256,background_generation,origin_observation_id,package,display_id,window_id,rotation,width,height,root_bounds,window_metadata_sha256,reported_windows_sha256,reported_windows_complete,ime_visibility,captured_elapsed_ms,full_native_complete,visited,pending,node_omissions,text_omissions,child_omissions");
    static final Set<String> IDENTITY=keys("task_id,owner_sha256,target_sha256,authorization_sha256,selection_sha256,installed_set_sha256,goal_sha256,background_generation,origin_observation_id");
    static final Set<String> FORM_IDS=keys("tv_depart_city,tv_arrival_city,tv_depart_date,tv_adult_count,tv_child_count,tv_baby_count,bt_submit_inquire");
    static final Set<String> ROLES=keys("列表页头部重新搜索,单程TripSwitcherCity,单程TripSwitcherDate,单程列表页,单程,往返,多程,经济舱");
    static final String[] TILE_IDS={"home_grid_hotel_widget","home_grid_flight_widget","home_grid_train_widget","home_grid_travel_widget","home_grid_strategy_widget"};
    static final Pattern DATE=Pattern.compile("([0-9]{1,2})月([0-9]{1,2})日(今天|明天|后天|周[一二三四五六日天])");
    private NativeActionSnapshotCheck(){}

    /** Values copied only from the same still-live private Session Attempt.
     * This data object is deliberately not an authority/capability token.
     * refSha256 is SHA-256 of the full Service NodeRef.signature UTF-8 string,
     * including scroll/IME/focus/input bindings; it is not appTreeSignature. */
    static final class Intent {
        final String purpose,pkg,path,label,refSha256,run,node,actionSha,historySha;
        final Map<String,Object> identity; final long started,deadline;
        Intent(String purpose,String pkg,String path,String label,String refSha256,String run,String node,
               String actionSha,String historySha,Map<String,Object> identity,long started,long deadline){
            need(Arrays.asList(OPEN,YEAR,QUERY,SEARCH).contains(purpose),"unsupported purpose");
            need((SEARCH.equals(purpose)?XIAOMI:CTRIP).equals(pkg),"purpose/package mismatch");
            need(path(path)&&label!=null&&label.length()<=4096&&sha(refSha256)&&id(run)&&node!=null&&node.matches("n[0-9]{1,4}")&&sha(actionSha),"original action identity");
            need(identity!=null&&identity.keySet().equals(IDENTITY),"exact authority identity");
            need(!QUERY.equals(purpose)||sha(historySha)&&!hash("").equals(historySha),"real query history binding missing");
            need(started>=0&&deadline>started&&deadline-started<=8000,"original action deadline");
            this.purpose=purpose;this.pkg=pkg;this.path=path;this.label=label;this.refSha256=refSha256;this.run=run;this.node=node;
            this.actionSha=actionSha;this.historySha=historySha;this.identity=freeze(identity);this.started=started;this.deadline=deadline;
        }
    }
    static final class Node {
        final Map<String,Object> v; final String path,pkg,cls,view,text,desc,parent,label; final List<Integer> bounds; final int children;
        Node(Map<String,Object> input){
            need(input!=null&&input.keySet().equals(NK),"complete exact node fields");v=freeze(input);
            path=s(v,"path");pkg=s(v,"package");cls=s(v,"class");view=s(v,"view_id");text=s(v,"text");desc=s(v,"description");parent=s(v,"parent_class");label=nullable(v,"label");
            need(path(path)&&!pkg.isEmpty()&&pkg.length()<=192&&!cls.isEmpty()&&cls.length()<=128&&parent.length()<=128&&view.length()<=256,"bounded complete node names");
            need(text.length()<=1024&&desc.length()<=1024&&(label==null||label.length()<=4096),"complete bounded text");
            need(s(v,"scroll_actions").length()<=1024&&s(v,"ime_enter").length()<=512,"bounded node action metadata");
            for(String k:Arrays.asList("visible","enabled","clickable","editable","scrollable","focused","password","selected","checkable","checked","action_click"))b(v,k);
            for(String k:Arrays.asList("ref_signature_sha256","input_sha256"))need(v.get(k)==null||sha(s(v,k)),"actual signature/hash");
            bounds=rect(v.get("bounds"));children=i(v,"children");need(children>=0&&children<=MAX_NODES&&i(v,"window_id")>=0,"children/window bounds");
        }
        boolean visible(){return b(v,"visible")&&bounds.get(2)>bounds.get(0)&&bounds.get(3)>bounds.get(1);}
        boolean usable(){return visible()&&b(v,"enabled")&&!b(v,"password");}
        boolean click(){return usable()&&b(v,"clickable")&&b(v,"action_click")&&!b(v,"editable");}
        boolean within(Node p){return under(path,p.path)&&contains(p.bounds,bounds);}
    }
    static final class Snapshot {
        final Map<String,Object> env; final Map<String,Node> nodes; final String sha;
        Snapshot(Map<String,Object> input,List<Node> list){
            need(input!=null&&input.keySet().equals(EK),"complete exact envelope");env=freeze(input);
            need(b(env,"full_native_complete")&&b(env,"reported_windows_complete")&&"hidden".equals(s(env,"ime_visibility")),"actual complete census/known hidden IME");
            for(String k:Arrays.asList("pending","node_omissions","text_omissions","child_omissions"))need(i(env,k)==0,"collection omitted "+k);
            for(String k:Arrays.asList("owner_sha256","target_sha256","authorization_sha256","selection_sha256","installed_set_sha256","goal_sha256","window_metadata_sha256","reported_windows_sha256"))need(sha(s(env,k)),"identity hash "+k);
            need(id(s(env,"task_id"))&&id(s(env,"origin_observation_id"))&&s(env,"background_generation").matches("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"),"task/observation/lease");
            need(i(env,"display_id")>0&&i(env,"window_id")>=0&&i(env,"rotation")>=0&&i(env,"rotation")<=3&&i(env,"width")>0&&i(env,"height")>0&&time(env,"captured_elapsed_ms")>=0,"display/clock");
            need(list!=null&&!list.isEmpty()&&list.size()<=MAX_NODES&&i(env,"visited")==list.size(),"full visited nodes, not retained subset");
            Map<String,Node> rows=new TreeMap<String,Node>();int chars=0;
            for(Node n:list){need(n!=null&&!rows.containsKey(n.path),"duplicate path");rows.put(n.path,n);
                need(n.pkg.equals(s(env,"package"))&&i(n.v,"window_id")==i(env,"window_id"),"foreign node/window");
                chars+=n.text.length()+n.desc.length();need(chars<=MAX_TEXT,"full text cap");}
            Node root=rows.get("0");need(root!=null&&root.visible()&&root.bounds.equals(rect(env.get("root_bounds"))),"actual root");
            for(Node n:rows.values()){
                if(!"0".equals(n.path)){Node p=rows.get(parent(n.path));need(p!=null&&n.parent.equals(p.cls)&&index(n.path)<p.children,"complete real parent/slot");}
                for(int x=0;x<n.children;x++)need(rows.containsKey(n.path+"/"+x),"missing child slot");
            }
            nodes=Collections.unmodifiableMap(rows);Map<String,Object> serial=new TreeMap<String,Object>();serial.put("envelope",env);
            List<Map<String,Object>> values=new ArrayList<Map<String,Object>>();for(Node n:rows.values())values.add(n.v);serial.put("nodes",values);
            String raw=canonical(serial);need(raw.getBytes(StandardCharsets.UTF_8).length<=MAX_BYTES,"full snapshot byte cap");sha=hash(raw);
        }
        Node node(String path){Node n=nodes.get(path);need(n!=null,"missing path: "+path);return n;}
    }
    static Map<String,Object> compare(Intent in,Snapshot old,Snapshot fresh,long now){
        need(in!=null&&old!=null&&fresh!=null,"two complete actual snapshots");
        for(String k:IDENTITY)need(in.identity.get(k).equals(old.env.get(k))&&in.identity.get(k).equals(fresh.env.get(k)),"binding changed: "+k);
        need(in.pkg.equals(s(old.env,"package"))&&in.pkg.equals(s(fresh.env,"package")),"App changed");
        long first=time(old.env,"captured_elapsed_ms"),last=time(fresh.env,"captured_elapsed_ms");
        need(first<=in.started&&in.started<=last&&last<=now&&now<in.deadline&&now-first<=90000,"original age/deadline/clock");
        Map<String,Object> a=new TreeMap<String,Object>(old.env),z=new TreeMap<String,Object>(fresh.env);
        for(String k:Arrays.asList("captured_elapsed_ms","visited")){a.remove(k);z.remove(k);}
        need(a.equals(z),"window/display/IME/authority differs");
        Node target=old.node(in.path),newTarget=fresh.node(in.path);
        need(target.click()&&newTarget.click()&&in.label.equals(target.label)&&in.refSha256.equals(target.v.get("ref_signature_sha256")),"original target/ref/label");
        need(target.v.equals(newTarget.v),"target facts changed");
        Scope before=scope(in,old),after=scope(in,fresh);
        need(before.roots.equals(after.roots)&&before.facts.equals(after.facts),"fresh purpose semantics differ");
        need(roleFacts(in,old).equals(roleFacts(in,fresh)),"global Provider roles/ambiguity changed");
        for(String p:before.ancestors)need(old.node(p).v.equals(fresh.node(p).v),"actual ancestor changed: "+p);
        for(String p:union(old.nodes.keySet(),fresh.nodes.keySet()))if(protectedPath(p,before.roots))
            need(old.nodes.containsKey(p)&&fresh.nodes.containsKey(p)&&old.node(p).v.equals(fresh.node(p).v),"complete protected subtree changed: "+p);
        Set<String> anchors=anchors(old,fresh,before);List<String> changed=new ArrayList<String>();
        for(String p:union(old.nodes.keySet(),fresh.nodes.keySet())){
            Node x=old.nodes.get(p),y=fresh.nodes.get(p);if(x!=null&&y!=null&&x.v.equals(y.v))continue;
            String found=null;for(String root:anchors)if(p.equals(root)||under(p,root)){need(found==null,"overlapping variable anchors");found=root;}
            need(found!=null,"change outside proved disjoint branch: "+p);changed.add(p);
        }
        Map<String,Object> out=new TreeMap<String,Object>();out.put("schema","hepta.native-action-snapshot-comparison.candidate.v1");
        out.put("purpose",in.purpose);out.put("target_path",in.path);out.put("model_run_id",in.run);out.put("original_node_id",in.node);
        out.put("original_action_sha256",in.actionSha);out.put("original_observation_id",in.identity.get("origin_observation_id"));
        out.put("before_snapshot_sha256",old.sha);out.put("fresh_snapshot_sha256",fresh.sha);out.put("semantic_sha256",hash(canonical(before.facts)));
        out.put("protected_subtrees",new ArrayList<String>(before.roots));out.put("checked_ancestors",new ArrayList<String>(before.ancestors));
        out.put("variable_branch_anchors",new ArrayList<String>(anchors));out.put("changed_paths",changed);out.put("changed_paths_truncated",false);
        out.put("query_history_binding_sha256",in.historySha);out.put("query_history_proved_by_comparator",false);
        out.put("grants_dispatch",false);out.put("provider_frame_constructed",false);out.put("session_observed_called",false);
        out.put("live_node_chain_window_and_one_effect_recheck_required",true);out.put("business_verified",false);return freeze(out);
    }
    private static final class Scope {
        final Set<String> roots=new TreeSet<String>(),ancestors=new TreeSet<String>();final Map<String,Object> facts=new TreeMap<String,Object>();
        void protect(Snapshot s,String path){Node n=s.node(path);need(n.usable(),"visible actual semantic container");roots.add(path);String p=path;
            while(true){Node a=s.node(p);need(a.usable()&&contains(a.bounds,n.bounds),"enabled actual containing ancestry");ancestors.add(p);if("0".equals(p))break;p=parent(p);}}
    }
    private static Scope scope(Intent in,Snapshot s){
        Scope out=new Scope();
        if(OPEN.equals(in.purpose)){
            noOverlay(s);need(findId(s,CP+"bt_submit_inquire").isEmpty()&&findId(s,CP+"calendar_month_title_left_tv").isEmpty()&&!role(s,"单程列表页"),"home-only page");
            Node tile=oneId(s,CP+"home_grid_flight_widget"),pager=s.node(parent(tile.path));need(tile.path.equals(in.path),"different home flight target");
            need("androidx.viewpager.widget.ViewPager".equals(pager.cls)&&"android.widget.FrameLayout".equals(pager.parent)&&pager.usable()&&b(pager.v,"scrollable")&&!b(pager.v,"editable"),"actual parent ViewPager");
            Node previous=null;for(int x=0;x<TILE_IDS.length;x++){Node n=oneId(s,CP+TILE_IDS[x]);
                need(n.path.equals(pager.path+"/"+x)&&n.within(pager)&&"android.view.ViewGroup".equals(n.cls)&&n.click()&&!b(n.v,"scrollable")&&!b(n.v,"selected")&&!b(n.v,"checkable")&&!b(n.v,"checked"),"same five tile siblings");
                if(previous!=null)need(previous.bounds.get(2)<=n.bounds.get(0)&&previous.bounds.get(1).equals(n.bounds.get(1))&&previous.bounds.get(3).equals(n.bounds.get(3)),"ordered same-row nonoverlapping tiles");
                previous=n;out.facts.put(TILE_IDS[x],n.v);}
            if(tile.label!=null&&!tile.label.isEmpty()){int count=0;for(Node n:s.nodes.values())if(n.usable()&&"机票".equals(n.text)&&n.within(tile))count++;need(count==1,"one same-tile flight label");}
            else need(tile.text.isEmpty()&&tile.desc.isEmpty()&&"".equals(tile.label),"original empty resource label, never inferred");
            out.protect(s,pager.path);
        }else if(YEAR.equals(in.purpose)||QUERY.equals(in.purpose)){
            noOverlay(s);List<Node> values=new ArrayList<Node>();for(String name:FORM_IDS){Node n=oneId(s,CP+name);values.add(n);out.facts.put(name,n.v);}
            Node from=oneId(s,CP+"tv_depart_city"),to=oneId(s,CP+"tv_arrival_city"),date=oneId(s,CP+"tv_depart_date"),query=oneId(s,CP+"bt_submit_inquire");
            need("北京".equals(from.text)&&"上海".equals(to.text)&&"1成人".equals(oneId(s,CP+"tv_adult_count").text)&&"0儿童".equals(oneId(s,CP+"tv_child_count").text)&&"0婴儿".equals(oneId(s,CP+"tv_baby_count").text),"same supported route/passengers");
            need(date.click()&&query.click()&&"查 询".equals(query.text),"actual date and normal query controls");
            Matcher m=DATE.matcher(date.text);need(m.matches(),"literal full form date");LocalDate.of(2000,Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)));
            String originalScope=parent(parent(query.path));for(Node n:values)need(under(n.path,originalScope),"same actual form scope");
            Node trip=oneDesc(s,"单程"),round=oneDesc(s,"往返"),multi=oneDesc(s,"多程"),economy=oneDesc(s,"经济舱");
            need(b(trip.v,"selected")&&!b(round.v,"selected")&&!b(multi.v,"selected")&&parent(trip.path).equals(parent(round.path))&&parent(trip.path).equals(parent(multi.path))&&under(trip.path,parent(originalScope)),"actual single-trip choice");
            need(b(economy.v,"selected")&&under(economy.path,originalScope),"actual economy choice");
            for(Node n:Arrays.asList(trip,round,multi,economy)){values.add(n);out.facts.put(n.desc,n.v);}
            need((YEAR.equals(in.purpose)?date:query).path.equals(in.path),"different purpose control");
            String root=commonParent(values);need(!"0".equals(root)&&!root.equals(parent(originalScope)),"bounded whole form container");
            out.protect(s,root);for(Node n:values)need(n.within(s.node(root)),"all semantic fields within actual form");
            out.facts.put("literal_departure_date",date.text);out.facts.put("year_inferred",false);
        }else{
            for(Node n:s.nodes.values())if(n.visible())need(!b(n.v,"editable")&&!"加入购物车".equals(n.text)&&!"立即购买".equals(n.text),"fresh home only, no input/detail phase");
            Node home=oneIdText(s,"com.xiaomi.shop.plugin.homepage:id/main_view_nav_bar_text","首页"),search=oneId(s,"com.xiaomi.shop.plugin.homepage:id/searchIcon");
            need("android.widget.TextView".equals(home.cls)&&b(home.v,"selected")&&"android.widget.ImageView".equals(search.cls)&&"搜索".equals(search.desc)&&search.click()&&search.bounds.get(3)<home.bounds.get(1)&&search.path.equals(in.path),"same actual selected home/search");
            need(!(hasText(s,"综合")&&hasText(s,"销量")&&hasText(s,"价格")),"not a results page");
            out.facts.put("home",home.v);out.facts.put("search",search.v);out.protect(s,parent(search.path));out.protect(s,parent(home.path));
        }return out;
    }
    private static Map<String,Object> roleFacts(Intent in,Snapshot s){Map<String,Object> out=new TreeMap<String,Object>();
        Set<String> xiaomi=keys("首页,搜索,加入购物车,立即购买,综合,销量,价格,Xiaomi路由器AX3000T,xiaomi路由器ax3000t");
        for(Node n:s.nodes.values()){
            boolean relevant;
            if(CTRIP.equals(in.pkg)){String shortId=n.view.startsWith(CP)?n.view.substring(CP.length()):"";
                relevant=FORM_IDS.contains(shortId)||Arrays.asList(TILE_IDS).contains(shortId)||"calendar_month_title_left_tv".equals(shortId)||"calendar_list".equals(shortId)||ROLES.contains(n.view)||ROLES.contains(n.desc)||"机票".equals(n.text);
            }else relevant=n.view.equals("com.xiaomi.shop.plugin.homepage:id/main_view_nav_bar_text")||n.view.equals("com.xiaomi.shop.plugin.homepage:id/searchIcon")||xiaomi.contains(n.text)||n.text.startsWith("Xiaomi路由器")||"android.widget.EditText".equals(n.cls)||b(n.v,"editable");
            if(relevant)out.put(n.path,n.v);
        }return out;
    }
    /** Roots are derived from the complete tree's real sibling relationships.
     * No numeric path (including 0/0/7) is whitelisted. All changed/new/deleted
     * descendants must be fully present in one of these fixed disjoint regions. */
    private static Set<String> anchors(Snapshot old,Snapshot fresh,Scope scope){Set<String> out=new TreeSet<String>();
        for(Node a:old.nodes.values()){
            if("0".equals(a.path)||scope.ancestors.contains(a.path)||protectedPath(a.path,scope.roots)||!scope.ancestors.contains(parent(a.path)))continue;
            Node z=fresh.nodes.get(a.path);if(z==null||!a.visible()||!z.visible())continue;
            Map<String,Object> x=new TreeMap<String,Object>(a.v),y=new TreeMap<String,Object>(z.v);
            for(String k:Arrays.asList("text","description","label","ref_signature_sha256","children")){x.remove(k);y.remove(k);}
            if(!x.equals(y))continue;boolean clear=true;
            for(String p:scope.roots)if(intersects(a.bounds,old.node(p).bounds))clear=false;
            if(clear&&neutral(old,a,scope)&&neutral(fresh,z,scope))out.add(a.path);
        }return out;
    }
    private static boolean neutral(Snapshot s,Node anchor,Scope scope){
        for(Node n:s.nodes.values())if(n.path.equals(anchor.path)||under(n.path,anchor.path)){
            for(String flag:Arrays.asList("editable","password","focused","checkable","checked","selected"))if(b(n.v,flag))return false;
            if(n.visible()){
                if(!contains(anchor.bounds,n.bounds))return false;
                for(String p:scope.roots)if(intersects(n.bounds,s.node(p).bounds))return false;
            }
        }return true;
    }
    private static void noOverlay(Snapshot s){for(String role:Arrays.asList("列表页头部重新搜索","单程TripSwitcherCity","单程TripSwitcherDate"))need(!role(s,role),"research overlay veto");}
    private static boolean role(Snapshot s,String value){for(Node n:s.nodes.values())if(n.usable()&&value.equals(n.view)&&value.equals(n.desc))return true;return false;}
    private static boolean hasText(Snapshot s,String text){for(Node n:s.nodes.values())if(n.usable()&&text.equals(n.text))return true;return false;}
    private static List<Node> findId(Snapshot s,String id){List<Node> out=new ArrayList<Node>();for(Node n:s.nodes.values())if(n.usable()&&id.equals(n.view))out.add(n);return out;}
    private static Node oneId(Snapshot s,String id){List<Node> out=findId(s,id);need(out.size()==1,"unique resource: "+id);return out.get(0);}
    private static Node oneIdText(Snapshot s,String id,String text){List<Node> out=new ArrayList<Node>();for(Node n:findId(s,id))if(text.equals(n.text))out.add(n);need(out.size()==1,"unique home marker");return out.get(0);}
    private static Node oneDesc(Snapshot s,String value){List<Node> out=new ArrayList<Node>();for(Node n:s.nodes.values())if(n.usable()&&"android.widget.LinearLayout".equals(n.cls)&&value.equals(n.desc))out.add(n);need(out.size()==1,"unique actual selection: "+value);return out.get(0);}
    private static String commonParent(List<Node> nodes){String p=parent(nodes.get(0).path);for(Node n:nodes)while(!under(n.path,p)){need(!"0".equals(p),"common actual ancestor");p=parent(p);}return p;}
    private static boolean protectedPath(String p,Set<String> roots){for(String root:roots)if(p.equals(root)||under(p,root))return true;return false;}
    private static boolean under(String p,String root){return p.startsWith(root+"/");}
    private static String parent(String p){int n=p.lastIndexOf('/');need(n>0,"actual parent missing");return p.substring(0,n);}
    private static int index(String p){return Integer.parseInt(p.substring(p.lastIndexOf('/')+1));}
    private static boolean path(String p){return p!=null&&p.length()<=240&&p.matches("0(?:/(?:0|[1-9][0-9]{0,3})){0,63}");}
    private static boolean contains(List<Integer> a,List<Integer> b){return a.get(0)<=b.get(0)&&a.get(1)<=b.get(1)&&a.get(2)>=b.get(2)&&a.get(3)>=b.get(3);}
    private static boolean intersects(List<Integer> a,List<Integer> b){return a.get(0)<b.get(2)&&b.get(0)<a.get(2)&&a.get(1)<b.get(3)&&b.get(1)<a.get(3);}
    static Set<String> keys(String csv){return Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(csv.split(","))));}
    private static Set<String> union(Set<String> a,Set<String> b){Set<String> out=new TreeSet<String>(a);out.addAll(b);return out;}
    static String s(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof String,"string: "+k);return(String)v;}
    private static String nullable(Map<String,Object> m,String k){return m.get(k)==null?null:s(m,k);}
    private static boolean b(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Boolean,"actual boolean: "+k);return(Boolean)v;}
    private static int i(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Integer,"integer: "+k);return(Integer)v;}
    private static long time(Map<String,Object> m,String k){Object v=m.get(k);need(v instanceof Long||v instanceof Integer,"integer time: "+k);return((Number)v).longValue();}
    @SuppressWarnings("unchecked") private static List<Integer> rect(Object v){need(v instanceof List&&((List<?>)v).size()==4,"full bounds");for(Object x:(List<?>)v)need(x instanceof Integer,"integer bounds");return(List<Integer>)v;}
    private static boolean id(String s){return s!=null&&s.matches("[0-9a-f]{32}");}
    private static boolean sha(String s){return s!=null&&s.matches("[0-9a-f]{64}");}
    private static void need(boolean yes,String message){if(!yes)throw new IllegalArgumentException(message);}
    private static Map<String,Object> freeze(Map<String,Object> m){Map<String,Object> out=new TreeMap<String,Object>();for(Map.Entry<String,Object> e:m.entrySet())out.put(e.getKey(),copy(e.getValue(),0));return Collections.unmodifiableMap(out);}
    private static Object copy(Object v,int depth){need(depth<16,"nesting budget");if(v==null||v instanceof String||v instanceof Boolean||v instanceof Integer||v instanceof Long)return v;
        if(v instanceof List){List<Object> out=new ArrayList<Object>();for(Object x:(List<?>)v)out.add(copy(x,depth+1));return Collections.unmodifiableList(out);}
        if(v instanceof Map){Map<String,Object> out=new TreeMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)v).entrySet()){need(e.getKey() instanceof String,"string key");out.put((String)e.getKey(),copy(e.getValue(),depth+1));}return Collections.unmodifiableMap(out);}throw new IllegalArgumentException("non-value in snapshot");}
    private static String canonical(Object v){StringBuilder out=new StringBuilder();canonical(v,out);return out.toString();}
    private static void canonical(Object v,StringBuilder out){if(v==null)out.append('n');else if(v instanceof String){String s=(String)v;out.append('s').append(s.getBytes(StandardCharsets.UTF_8).length).append(':').append(s);}else if(v instanceof Boolean)out.append(Boolean.TRUE.equals(v)?'t':'f');else if(v instanceof Number)out.append('i').append(v).append(';');else if(v instanceof List){out.append('[');for(Object x:(List<?>)v)canonical(x,out);out.append(']');}else if(v instanceof Map){out.append('{');for(Map.Entry<?,?> e:((Map<?,?>)v).entrySet()){canonical(e.getKey(),out);canonical(e.getValue(),out);}out.append('}');}else throw new IllegalArgumentException("noncanonical value");}
    static String hash(String value){try{byte[] b=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));StringBuilder out=new StringBuilder();for(byte x:b)out.append(String.format(java.util.Locale.ROOT,"%02x",x&255));return out.toString();}catch(Exception e){throw new IllegalStateException(e);}}
}
