package org.trillionnium.hepta.local;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Current native Xiaomi App facts. This parser cannot dispatch, submit an order,
 * create a result capability, prove an installed App, or complete a task.
 * The caller must own the immutable goal and exact current Frame. */
final class NativeXiaomiProductPage {
    static final String SCHEMA="hepta.native-xiaomi-product-page.v1";
    static final String IMAGE_MODAL="image_modal";
    static final String HOME_LOADING="home_loading",HOME_LOADING_EXHAUSTED="home_loading_budget_exhausted";
    static final String LOGIN="native_login",LOGIN_BLOCKED="native_login_requires_user";
    static final String LOGIN_EXIT="leave_native_login_once";
    static final String SEARCH_ICON="open_search_icon";
    private static final String TITLE="Xiaomi路由器AX3000T";
    private static final String VIEW="android.view.ViewGroup";
    private static final String TEXT="android.widget.TextView";
    private static final String MONEY="(?:0|[1-9][0-9]{0,7})(?:\\.[0-9]{1,2})?";
    private static final Pattern NUMBER=Pattern.compile(MONEY);
    private static final Pattern SECONDARY=Pattern.compile("[¥￥]("+MONEY+")");
    private static final Pattern DETAIL=Pattern.compile("("+MONEY+")元划线价("+MONEY+")元");
    private static final Pattern PROMOTION=Pattern.compile("(?:分期最高减"+MONEY+"元|分期立减|预计得[0-9]{1,8}米金)");
    private NativeXiaomiProductPage(){}

    static final class Page {
        final NativeAppEvidence.Frame frame;
        final String phase;
        final List<String> missing;
        final Set<String> clickIds;
        final Map<String,String> editValues,purposes;
        final Quote quote;
        final boolean searchIconNavigationCandidate;
        private final Map<String,Object> record;
        private Page(NativeAppEvidence.Frame frame,String phase,List<String> missing,
                Set<String> clicks,Map<String,String> edits,Map<String,String> purposes,
                Map<String,Object> actionFacts,Quote quote){
            this(frame,phase,missing,clicks,edits,purposes,actionFacts,quote,false);
        }
        private Page(NativeAppEvidence.Frame frame,String phase,List<String> missing,
                Set<String> clicks,Map<String,String> edits,Map<String,String> purposes,
                Map<String,Object> actionFacts,Quote quote,boolean searchIconNavigationCandidate){
            this.frame=frame;this.phase=phase;this.searchIconNavigationCandidate=searchIconNavigationCandidate;
            this.missing=Collections.unmodifiableList(new ArrayList<String>(missing));
            clickIds=Collections.unmodifiableSet(new LinkedHashSet<String>(clicks));
            editValues=Collections.unmodifiableMap(new LinkedHashMap<String,String>(edits));
            this.purposes=Collections.unmodifiableMap(new LinkedHashMap<String,String>(purposes));this.quote=quote;
            Map<String,Object> e=map();e.put("schema",SCHEMA);e.put("frame",frame.evidence());e.put("phase",phase);
            e.put("missing",this.missing);e.put("click_node_ids",clickIds);e.put("edit_values",editValues);
            e.put("purposes",this.purposes);e.put("current_action_source_facts",actionFacts);
            e.put("quote",quote==null?null:quote.evidence());
            e.put("installed_identity_verified_here",false);e.put("dispatch_authority",false);
            e.put("query_dispatched",false);e.put("task_completion_authority",false);
            e.put("order_submitted",false);
            if(searchIconNavigationCandidate){
                e.put("navigation_candidate","stable_search_icon");
                e.put("navigation_semantics_device_verified",false);
                e.put("fresh_search_contract_required",true);
            }
            record=frozen(e);
        }
        Map<String,Object> evidence(){return record;}
        Map<String,Object> modelView(){
            Map<String,Object> e=map();e.put("schema",SCHEMA);e.put("phase",phase);e.put("missing",missing);
            e.put("click_node_ids",clickIds);e.put("edit_values",editValues);e.put("purposes",purposes);
            if(quote!=null)e.put("current_displayed_quote",quote.modelView());
            e.put("purchase_actions_available",false);return frozen(e);
        }
    }

    static final class Quote {
        final NativeAppEvidence.Frame frame;
        final String kind,modelRaw,amountDecimal,currency,comparisonAmountDecimal,comparisonKind;
        final String fingerprint,semanticFingerprint;
        final List<Map<String,Object>> conditions;
        private final Map<String,Object> record,view;
        private Quote(NativeAppEvidence.Frame frame,String kind,NativeAppEvidence.Node model,
                String amount,String comparison,String comparisonKind,List<Map<String,Object>> conditions,
                List<Map<String,Object>> sources,Map<String,Object> membership){
            this.frame=frame;this.kind=kind;modelRaw=model.text;amountDecimal=decimal(amount);currency="CNY";
            comparisonAmountDecimal=comparison==null?null:decimal(comparison);this.comparisonKind=comparisonKind;
            this.conditions=immutableFacts(conditions);
            Map<String,Object> semantic=map();semantic.put("quote_kind",kind);semantic.put("model_raw",modelRaw);
            semantic.put("amount_decimal",amountDecimal);semantic.put("currency",currency);
            semantic.put("comparison_amount_decimal",comparisonAmountDecimal);semantic.put("comparison_kind",comparisonKind);
            List<Object> rawConditions=new ArrayList<Object>();
            for(Map<String,Object> fact:conditions)rawConditions.add(fact.get("raw"));
            semantic.put("visible_promotion_texts",rawConditions);
            semanticFingerprint=NativeAppEvidence.fingerprint(semantic);
            Map<String,Object> e=map();e.put("schema","hepta.native-xiaomi-displayed-quote.v1");
            e.put("frame",frame.evidence());e.putAll(semantic);e.put("conditions",this.conditions);
            e.put("sources",immutableFacts(sources));e.put("same_product_membership",membership);
            e.put("semantic_fingerprint",semanticFingerprint);
            e.put("currency_basis","current_pinned_Xiaomi_China_App_currency_format");
            e.put("promotions_deducted_from_amount",false);e.put("lowest_price_verified",false);
            e.put("selected_sku_verified",false);e.put("delivery_address_verified",false);
            e.put("inventory_verified",false);e.put("final_checkout_price_verified",false);
            e.put("order_submitted",false);e.put("query_dispatched",false);e.put("task_complete",false);
            fingerprint=NativeAppEvidence.fingerprint(e);e.put("fingerprint",fingerprint);record=frozen(e);
            Map<String,Object> m=map();m.putAll(semantic);m.put("scope","current_visible_App_display_only");
            m.put("promotions_deducted_from_amount",false);m.put("selected_sku_verified",false);
            m.put("final_checkout_price_verified",false);m.put("order_submitted",false);view=frozen(m);
        }
        Map<String,Object> evidence(){return record;}
        Map<String,Object> modelView(){return view;}
    }

    /** Retained switcher parser: its historical fixtures and scope are unchanged. */
    static Page inspect(NativeAppGoal goal,NativeAppEvidence.Frame frame){
        return inspect(goal,frame,false);
    }
    /** A current, exact icon can be proposed as navigation; this is not proof
     * that it opens an editor. Only a fresh existing search contract can do that. */
    static Page inspectPreferredNavigation(NativeAppGoal goal,NativeAppEvidence.Frame frame){
        return inspect(goal,frame,true);
    }
    private static Page inspect(NativeAppGoal goal,NativeAppEvidence.Frame frame,boolean preferSearchIcon){
        NativeAppEvidence.need(goal!=null&&frame!=null,"Xiaomi goal and actual frame required");
        NativeAppEvidence.need(NativeAppGoal.PRODUCT_PRICE.equals(goal.kind)
                &&NativeAppGoal.XIAOMI_PACKAGE.equals(goal.packageName)
                &&NativeAppGoal.PRODUCT_MODEL.equals(goal.productModel),"recognized literal Xiaomi product-price goal required");
        NativeAppEvidence.need(goal.ownerSha256.equals(frame.ownerSha)&&goal.packageName.equals(frame.packageName),
                "Xiaomi page differs from immutable owner/package");
        if(!frame.metadataObserved||frame.windowType!=1)return unavailable(frame,"observed_application_window_required");
        if(!frame.collectionComplete||frame.nodesTruncated)return unavailable(frame,"complete_bounded_observation_required");
        for(NativeAppEvidence.Node node:frame.nodes)
            if(!frame.packageName.equals(node.packageName))return unavailable(frame,"foreign_node_package");
        Page login=nativeLogin(frame);if(login!=null)return login;
        if(imageModal(frame))return page(frame,IMAGE_MODAL,"image_modal_content_unclassified",null,null);
        List<NativeAppEvidence.Node> models=exactText(frame,TITLE);
        boolean detailMarkers=uniqueText(frame,"加入购物车")!=null&&uniqueText(frame,"立即购买")!=null;
        if(detailMarkers)return detail(goal,frame,models);
        if(uniqueText(frame,"综合")!=null&&uniqueText(frame,"销量")!=null&&uniqueText(frame,"价格")!=null)
            return results(goal,frame,models);
        return inputOrHome(goal,frame,preferSearchIcon);
    }

    /** Recognizes the complete observed login form for the pinned native App.
     * Only its literal return control is a navigation candidate. Login, consent,
     * account input and external-account controls never become action targets.
     */
    private static Page nativeLogin(NativeAppEvidence.Frame frame){
        if(frame.left!=0||frame.top!=0||frame.right!=frame.width||frame.bottom!=frame.height
                ||frame.nodes.size()!=13)return null;
        NativeAppEvidence.Node back=loginNode(frame,"0/0","android.widget.ImageView","back","","返回",true,false,false);
        NativeAppEvidence.Node title=loginNode(frame,"0/3/0",TEXT,"","小米账号登录","",false,false,false);
        NativeAppEvidence.Node input=loginNode(frame,"0/3/2","android.widget.AutoCompleteTextView","input","请输入手机号","",true,true,false);
        NativeAppEvidence.Node agreement=loginNode(frame,"0/3/4",TEXT,"user_agreement_hint","已阅读并同意本应用用户协议 隐私政策、小米账号用户协议 隐私政策","",false,false,false);
        NativeAppEvidence.Node next=loginNode(frame,"0/3/5","android.widget.Button","get_login_type","下一步","",true,false,false);
        NativeAppEvidence.Node password=loginNode(frame,"0/3/6","android.widget.Button","password_login","密码登录","",true,false,false);
        if(back==null||title==null||input==null||agreement==null||next==null||password==null
                ||loginNode(frame,"0/1",TEXT,"help","帮助","",true,false,false)==null
                ||loginNode(frame,"0/4",TEXT,"tv_other_login_way","其他登录方式","",false,false,false)==null
                ||loginNode(frame,"0/5","android.widget.ImageView","sdk_wechat_auth","","微信登录",true,false,false)==null
                ||loginNode(frame,"0/6","android.widget.ImageView","sdk_qq_auth","","QQ登录",true,false,false)==null
                ||loginNode(frame,"0/7","android.widget.ImageView","sdk_weibo_auth","","微博登录",true,false,false)==null
                ||loginNode(frame,"0/3/1",TEXT,"country_code","+86","",true,false,false)==null
                ||loginNode(frame,"0/3/3","android.widget.CheckBox","user_agreement_checkbox","","",true,false,true)==null)
            return null;
        Map<String,Object> facts=map();facts.put("return_control",back.fact("description"));
        facts.put("login_title",title.fact("text"));facts.put("empty_phone_prompt",input.fact("text"));
        facts.put("agreement_text",agreement.fact("text"));facts.put("next_label",next.fact("text"));
        facts.put("password_login_label",password.fact("text"));facts.put("public_browsing_requires_login_verified",false);
        facts.put("credentials_or_agreement_actions_available",false);
        return new Page(frame,LOGIN,Collections.singletonList("native_login_page_observed"),
                Collections.singleton(back.id),Collections.<String,String>emptyMap(),
                Collections.singletonMap(back.id,LOGIN_EXIT),facts,null);
    }
    private static NativeAppEvidence.Node loginNode(NativeAppEvidence.Frame frame,String path,String cls,String resource,
            String text,String description,boolean clickable,boolean editable,boolean checkable){
        NativeAppEvidence.Node found=null;
        for(NativeAppEvidence.Node node:frame.nodes)if(path.equals(node.path)){
            if(found!=null)return null;found=node;
        }
        if(!usable(frame,found)||!cls.equals(found.className)
                ||!(resource.isEmpty()?"":"com.xiaomi.shop:id/"+resource).equals(found.viewId)
                ||!text.equals(found.text)||!description.equals(found.description)
                ||!(text.isEmpty()?description:text).equals(found.label)
                ||!(path.startsWith("0/3/")?"android.widget.ScrollView":"android.widget.FrameLayout").equals(found.parentClass)
                ||found.clickable!=clickable||found.editable!=editable||found.scrollable||!found.scrollDirections.isEmpty()
                ||!Boolean.FALSE.equals(found.selected)||!Boolean.valueOf(checkable).equals(found.checkable)
                ||!Boolean.FALSE.equals(found.checked))return null;
        return found;
    }

    /** Only the observed image-window shape is classified. This does not identify
     * promotional content, a close button, consent, or a safe click. The bound
     * Session may separately permit one pre-query Back and require a fresh home.
     */
    private static boolean imageModal(NativeAppEvidence.Frame frame){
        if(frame.left<=0||frame.top<=0||frame.right>=frame.width||frame.bottom>=frame.height
                ||frame.nodes.size()!=2)return false;
        NativeAppEvidence.Node image=null,small=null;
        for(NativeAppEvidence.Node n:frame.nodes){
            // Any observed text, description, derived label, or resource id
            // rejects this path, including login/privacy/consent dialogs.
            if(!usable(frame,n)||!"android.widget.ImageView".equals(n.className)
                    ||!"android.widget.FrameLayout".equals(n.parentClass)||!n.clickable
                    ||n.editable||n.scrollable||!n.scrollDirections.isEmpty()
                    ||!n.text.isEmpty()||!n.description.isEmpty()||!n.label.isEmpty()||!n.viewId.isEmpty()
                    ||!Boolean.FALSE.equals(n.selected)||!Boolean.FALSE.equals(n.checkable)
                    ||!Boolean.FALSE.equals(n.checked))return false;
            if("0/0".equals(n.path))image=n;
            else if("0/1".equals(n.path))small=n;
            else return false;
        }
        if(image==null||small==null)return false;
        long smallWidth=(long)small.right-small.left,smallHeight=(long)small.bottom-small.top;
        long gap=(long)small.top-image.bottom;
        return image.left==frame.left&&image.top==frame.top&&image.right==frame.right
                &&small.bottom==frame.bottom&&smallWidth==smallHeight
                &&smallWidth<(long)image.right-image.left&&smallHeight<(long)image.bottom-image.top
                &&(long)small.left+small.right==(long)frame.left+frame.right
                &&gap>0&&gap<=smallHeight;
    }

    private static Page detail(NativeAppGoal goal,NativeAppEvidence.Frame frame,List<NativeAppEvidence.Node> models){
        if(models.size()!=1)return page(frame,"product_detail_unverified","unique_visible_exact_product_title_required",null,null);
        NativeAppEvidence.Node model=models.get(0),price=null;Matcher priceMatch=null;
        for(NativeAppEvidence.Node node:frame.nodes){
            Matcher found=DETAIL.matcher(node.description);
            if(usable(frame,node)&&VIEW.equals(node.className)&&!node.clickable&&found.matches()){
                if(price!=null)return page(frame,"product_detail_unverified","unique_accessible_price_description_required",null,null);
                price=node;priceMatch=found;
            }
        }
        if(price==null)return page(frame,"product_detail_unverified","unambiguous_accessible_price_description_required",null,null);
        String block=commonParent(price.path,model.path);
        if(block==null||distance(price.path,block)!=2||distance(model.path,block)!=2
                ||!VIEW.equals(price.parentClass)||!VIEW.equals(model.parentClass)
                ||price.top>=model.top||price.bottom>model.bottom)
            return page(frame,"product_detail_unverified","title_and_price_product_block_not_proved",null,null);
        for(NativeAppEvidence.Node node:frame.nodes){
            if(!under(node.path,block)||!usable(frame,node)||node==model)continue;
            if(node.text.startsWith("Xiaomi路由器")||DETAIL.matcher(node.description).matches()&&node!=price)
                return page(frame,"product_detail_unverified","ambiguous_product_block",null,null);
        }
        List<Map<String,Object>> sources=new ArrayList<Map<String,Object>>();
        sources.add(model.fact("text"));sources.add(price.fact("description"));
        List<Map<String,Object>> ignoredRichText=new ArrayList<Map<String,Object>>();
        for(NativeAppEvidence.Node node:frame.nodes){
            if(usable(frame,node)&&TEXT.equals(node.className)&&parent(node.path).equals(price.path)&&!node.text.isEmpty()){
                // This renderer concatenates styled spans (actual example:
                // "￥1590￥199"). It is retained, never parsed as the amount.
                ignoredRichText.add(node.fact("text"));
            }
        }
        Map<String,Object> membership=map();membership.put("native_common_product_block_path",block);
        membership.put("model_fact",model.fact("text"));membership.put("price_fact",price.fact("description"));
        membership.put("price_source","complete_accessibility_description");
        membership.put("merged_child_text_used_as_amount",false);membership.put("ignored_merged_child_text",ignoredRichText);
        membership.put("offscreen_sku_or_address_used",false);
        try{
            Quote quote=new Quote(frame,"detail_display",model,priceMatch.group(1),priceMatch.group(2),
                    "explicit_strikethrough_label",promotions(frame),sources,membership);
            return page(frame,"product_detail_quote",null,null,quote);
        }catch(IllegalArgumentException invalidAmount){
            return page(frame,"product_detail_unverified","invalid_observed_amount",null,null);
        }
    }

    private static Page results(NativeAppGoal goal,NativeAppEvidence.Frame frame,List<NativeAppEvidence.Node> models){
        if(models.size()!=1)return page(frame,"search_results_unverified","unique_visible_exact_product_card_required",null,null);
        NativeAppEvidence.Node model=models.get(0),card=clickAncestor(frame,model);
        if(card==null||!VIEW.equals(card.className)||distance(model.path,card.path)!=2)
            return page(frame,"search_results_unverified","actual_clickable_product_card_required",null,null);
        String group=parent(model.path);
        List<NativeAppEvidence.Node> amounts=new ArrayList<NativeAppEvidence.Node>(),symbols=new ArrayList<NativeAppEvidence.Node>(),secondary=new ArrayList<NativeAppEvidence.Node>();
        for(NativeAppEvidence.Node node:frame.nodes){
            if(!under(node.path,card.path)||!usable(frame,node))continue;
            if(node!=model&&node.text.startsWith("Xiaomi路由器"))
                return page(frame,"search_results_unverified","multiple_products_in_card",null,null);
            if(!parent(node.path).equals(group)||!TEXT.equals(node.className)||!node.within(card))continue;
            if(NUMBER.matcher(node.text).matches())amounts.add(node);
            if("￥".equals(node.text)||"¥".equals(node.text))symbols.add(node);
            if(SECONDARY.matcher(node.text).matches())secondary.add(node);
        }
        if(amounts.size()!=1||symbols.size()!=1||secondary.size()>1)
            return page(frame,"search_results_unverified","unambiguous_same_card_price_nodes_required",card,null);
        NativeAppEvidence.Node amount=amounts.get(0),symbol=symbols.get(0);
        if(!adjacent(symbol,amount)||amount.top<=model.bottom)
            return page(frame,"search_results_unverified","same_row_adjacent_currency_and_amount_required",card,null);
        String comparison=null;NativeAppEvidence.Node compared=secondary.isEmpty()?null:secondary.get(0);
        if(compared!=null){
            if(!adjacent(amount,compared))return page(frame,"search_results_unverified","same_row_secondary_amount_required",card,null);
            Matcher m=SECONDARY.matcher(compared.text);
            if(!m.matches())throw new IllegalStateException("checked secondary amount changed");
            comparison=m.group(1);
        }
        List<Map<String,Object>> sources=new ArrayList<Map<String,Object>>();
        sources.add(model.fact("text"));sources.add(symbol.fact("text"));sources.add(amount.fact("text"));
        if(compared!=null)sources.add(compared.fact("text"));
        Map<String,Object> membership=map();membership.put("actual_clickable_card",card.fact("description"));
        membership.put("native_same_parent_path",group);membership.put("all_price_nodes_within_card",true);
        membership.put("price_source","same_card_adjacent_currency_and_amount");
        membership.put("comparison_strikethrough_semantics_observed",false);
        try{
            Quote quote=new Quote(frame,"search_card",model,amount.text,comparison,
                    compared==null?null:"secondary_display_amount",Collections.<Map<String,Object>>emptyList(),sources,membership);
            return page(frame,"search_results_quote",null,card,quote);
        }catch(IllegalArgumentException invalidAmount){
            return page(frame,"search_results_unverified","invalid_observed_amount",card,null);
        }
    }

    /** The archived ordinary App toolbar uses a FrameLayout root and direct
     * sibling slots. Its two real TextView labels distinguish normal search
     * from the mode toggle; a derived label or nearby blank control is not proof. */
    private static Page frameLayoutInput(NativeAppGoal goal,NativeAppEvidence.Frame frame,NativeAppEvidence.Node field){
        if(!"0/1".equals(field.path)||!field.viewId.isEmpty()||!field.clickable||field.scrollable
                ||!field.scrollDirections.isEmpty()||!unselected(field))
            return page(frame,"search_input_unverified","observed_frame_layout_query_field_required",null,null);
        NativeAppEvidence.Node normal=null,normalLabel=null,toggle=null,toggleLabel=null;int labels=0;
        for(NativeAppEvidence.Node label:exactText(frame,"搜索")){
            NativeAppEvidence.Node button=clickAncestor(frame,label);
            if(button==null||!"0".equals(parent(button.path)))continue;
            labels++;
            if(!VIEW.equals(button.className)||!"android.widget.FrameLayout".equals(button.parentClass)
                    ||!button.viewId.isEmpty()||!button.text.isEmpty()||!button.description.isEmpty()
                    ||button.editable||button.scrollable||!button.scrollDirections.isEmpty()||!unselected(button)
                    ||!VIEW.equals(label.parentClass)||!label.viewId.isEmpty()||!label.description.isEmpty()
                    ||label.clickable||label.editable||label.scrollable||!label.scrollDirections.isEmpty()||!unselected(label)
                    ||distance(label.path,button.path)!=1||childIndex(label.path)!=0)
                return page(frame,"search_input_unverified","observed_frame_layout_search_controls_required",null,null);
            if("0/4".equals(button.path)){if(normal!=null)return page(frame,"search_input_unverified","duplicate_normal_search_button",null,null);
                normal=button;normalLabel=label;}
            else if("0/0".equals(button.path)){if(toggle!=null)return page(frame,"search_input_unverified","duplicate_search_mode_toggle",null,null);
                toggle=button;toggleLabel=label;}
        }
        if(labels!=2||normal==null||toggle==null||normal==toggle
                ||toggle.right>=normal.left||toggle.left>field.left||normal.right<field.right
                ||toggle.top<field.top||normal.top<field.top
                ||Math.min(toggle.bottom,normal.bottom)<=Math.max(toggle.top,normal.top))
            return page(frame,"search_input_unverified","normal_search_and_mode_toggle_not_distinguished",null,null);
        if(!directRootSearchToolbar(frame,field,normal,normalLabel,toggle,toggleLabel))
            return page(frame,"search_input_unverified","observed_direct_root_search_toolbar_required",null,null);
        Map<String,Object> proof=map();proof.put("query_field",field.fact("text"));
        proof.put("normal_search_button",normal.fact("description"));proof.put("normal_search_label",normalLabel.fact("text"));
        proof.put("excluded_mode_toggle",toggle.fact("description"));proof.put("excluded_mode_toggle_label",toggleLabel.fact("text"));
        proof.put("same_native_toolbar_path","0");proof.put("toolbar_shape","observed_frame_layout_direct_children.v1");
        proof.put("mode_toggle_offered",false);proof.put("derived_label_grants_authority",false);
        proof.put("search_toolbar_variant","direct_root_framelayout");
        String literal=goal.immutableOwner.substring(goal.modelStartUtf16,goal.modelEndUtf16);
        Map<String,String> purposes=new LinkedHashMap<String,String>();Map<String,Object> facts=map();
        if(!field.text.equals(literal)){
            Map<String,String> edits=new LinkedHashMap<String,String>();edits.put(field.id,literal);
            purposes.put(field.id,"set_product_query");facts.put(field.id,proof);
            return new Page(frame,"search_input",Collections.<String>emptyList(),Collections.<String>emptySet(),edits,purposes,facts,null);
        }
        // No unobserved suggestion layout is admitted by this distinct template.
        purposes.put(normal.id,"submit_product_query");facts.put(normal.id,proof);
        return new Page(frame,"search_submit",Collections.<String>emptyList(),Collections.singleton(normal.id),
                Collections.<String,String>emptyMap(),purposes,facts,null);
    }
    private static boolean unselected(NativeAppEvidence.Node node){
        return Boolean.FALSE.equals(node.selected)&&Boolean.FALSE.equals(node.checkable)&&Boolean.FALSE.equals(node.checked);
    }

    private static Page inputOrHome(NativeAppGoal goal,NativeAppEvidence.Frame frame,boolean preferSearchIcon){
        List<NativeAppEvidence.Node> fields=new ArrayList<NativeAppEvidence.Node>();
        for(NativeAppEvidence.Node n:frame.nodes)
            if(usable(frame,n)&&n.editable&&"android.widget.EditText".equals(n.className))fields.add(n);
        if(fields.size()>1)return page(frame,"search_input_unverified","unique_native_query_field_required",null,null);
        if(fields.size()==1){
            NativeAppEvidence.Node field=fields.get(0);
            if("android.widget.FrameLayout".equals(field.parentClass))return frameLayoutInput(goal,frame,field);
            String toolbar=parent(field.path);
            int fieldIndex=childIndex(field.path);
            if(!VIEW.equals(field.parentClass)||(fieldIndex!=1&&fieldIndex!=2))
                return page(frame,"search_input_unverified","observed_search_toolbar_required",null,null);
            NativeAppEvidence.Node normal=null,normalLabel=null,toggle=null,toggleLabel=null;
            int labels=0;
            for(NativeAppEvidence.Node n:exactText(frame,"搜索")){
                NativeAppEvidence.Node button=clickAncestor(frame,n);
                if(button==null||!parent(button.path).equals(toolbar)||distance(n.path,button.path)!=1
                        ||!VIEW.equals(button.className))continue;
                labels++;
                if(childIndex(button.path)==3&&childIndex(n.path)==1){
                    if(normal!=null)return page(frame,"search_input_unverified","duplicate_normal_search_button",null,null);
                    normal=button;normalLabel=n;
                }else if(childIndex(button.path)==fieldIndex-1&&childIndex(n.path)==2){
                    if(toggle!=null)return page(frame,"search_input_unverified","duplicate_search_mode_toggle",null,null);
                    toggle=button;toggleLabel=n;
                }
            }
            if(labels!=2||normal==null||toggle==null||normal==toggle
                    ||toggle.right>=normal.left||toggle.left>field.left||normal.right<field.right
                    ||toggle.top<field.top||normal.top<field.top
                    ||Math.min(toggle.bottom,normal.bottom)<=Math.max(toggle.top,normal.top))
                return page(frame,"search_input_unverified","normal_search_and_mode_toggle_not_distinguished",null,null);
            Map<String,Object> proof=map();proof.put("query_field",field.fact("text"));
            proof.put("normal_search_button",normal.fact("description"));proof.put("normal_search_label",normalLabel.fact("text"));
            proof.put("excluded_mode_toggle",toggle.fact("description"));proof.put("excluded_mode_toggle_label",toggleLabel.fact("text"));
            proof.put("same_native_toolbar_path",toolbar);proof.put("mode_toggle_offered",false);
            String literal=goal.immutableOwner.substring(goal.modelStartUtf16,goal.modelEndUtf16);
            if(!field.text.equals(literal)){
                Map<String,String> edits=new LinkedHashMap<String,String>();edits.put(field.id,literal);
                Map<String,String> purposes=new LinkedHashMap<String,String>();purposes.put(field.id,"set_product_query");
                Map<String,Object> facts=map();facts.put(field.id,proof);
                return new Page(frame,"search_input",Collections.<String>emptyList(),Collections.<String>emptySet(),edits,purposes,facts,null);
            }
            String panel=parent(parent(toolbar));
            List<NativeAppEvidence.Node> exactSuggestions=exactText(frame,"xiaomi路由器ax3000t");
            NativeAppEvidence.Node suggestion=null;
            if(exactSuggestions.size()==1){
                NativeAppEvidence.Node label=exactSuggestions.get(0),button=clickAncestor(frame,label);
                String prefix=panel+"/2/0/0/";
                if(button!=null&&VIEW.equals(button.className)&&button.path.startsWith(prefix)
                        &&button.path.substring(prefix.length()).matches("(?:0|[1-9][0-9]{0,2})/0/0/0")
                        &&distance(label.path,button.path)==1&&childIndex(label.path)==0
                        &&button.right-button.left>=field.right-field.left&&button.top>=normal.bottom){
                    suggestion=button;proof.put("exact_suggestion_label",label.fact("text"));
                    proof.put("exact_suggestion_button",button.fact("description"));
                    proof.put("suggestion_branch_path",prefix);
                }
            }
            // The real reset fixture exposes both foreground suggestions and
            // same-text history. Never choose either by whole-tree first match.
            NativeAppEvidence.Node chosen=suggestion==null?normal:suggestion;
            String purpose=suggestion==null?"submit_product_query":"submit_exact_suggestion";
            proof.put("same_text_candidate_count",exactSuggestions.size());
            proof.put("ambiguous_suggestion_uses_verified_normal_button",suggestion==null);
            Map<String,String> purposes=new LinkedHashMap<String,String>();purposes.put(chosen.id,purpose);
            Map<String,Object> facts=map();facts.put(chosen.id,proof);
            return new Page(frame,suggestion==null?"search_submit":"search_suggestion",Collections.<String>emptyList(),
                    Collections.singleton(chosen.id),Collections.<String,String>emptyMap(),purposes,facts,null);
        }
        NativeAppEvidence.Node home=null,search=null;
        for(NativeAppEvidence.Node n:frame.nodes){
            if(!usable(frame,n))continue;
            if("com.xiaomi.shop.plugin.homepage:id/main_view_nav_bar_text".equals(n.viewId)
                    &&TEXT.equals(n.className)&&"首页".equals(n.text)&&Boolean.TRUE.equals(n.selected)){
                if(home!=null)return page(frame,"home_unverified","duplicate_selected_home_marker",null,null);home=n;
            }
            if("com.xiaomi.shop.plugin.homepage:id/searchIcon".equals(n.viewId)
                    &&"android.widget.ImageView".equals(n.className)&&"搜索".equals(n.description)&&n.clickable){
                if(search!=null)return page(frame,"home_unverified","duplicate_home_search_icon",null,null);search=n;
            }
        }
        if(home!=null&&search!=null&&search.bottom<home.top){
            Page entry=homeSearchEntry(frame,home,search,preferSearchIcon);
            return entry!=null?entry:page(frame,"home_unverified","observed_native_query_entry_required",null,null);
        }
        if(home!=null&&search==null&&navigationOnlyHome(frame))
            return page(frame,HOME_LOADING,"native_home_search_content_not_loaded",null,null);
        return page(frame,"unrecognized_native_page","no_current_supported_native_page",null,null);
    }

    /** Exact observed root toolbar. Its two literal labels identify separate
     * current controls, not an arbitrary same-text history row or a coordinate.
     * No root-variant suggestion has been qualified; only its right button can
     * submit after the actual editable field contains the immutable query. */
    private static boolean directRootSearchToolbar(NativeAppEvidence.Frame frame,NativeAppEvidence.Node field,
            NativeAppEvidence.Node normal,NativeAppEvidence.Node normalLabel,
            NativeAppEvidence.Node toggle,NativeAppEvidence.Node toggleLabel){
        NativeAppEvidence.Node[] nodes={field,normal,normalLabel,toggle,toggleLabel};
        String[] paths={"0/1","0/4","0/4/0","0/0","0/0/0"};
        for(int i=0;i<nodes.length;i++){
            NativeAppEvidence.Node n=nodes[i];boolean label=i==2||i==4;
            if(!usable(frame,n)||!paths[i].equals(n.path)||!n.viewId.isEmpty()
                    ||!(label?VIEW:"android.widget.FrameLayout").equals(n.parentClass)
                    ||n.scrollable||!Boolean.FALSE.equals(n.selected)||!Boolean.FALSE.equals(n.checkable)||!Boolean.FALSE.equals(n.checked)
                    ||n.clickable==label||n.editable!=(i==0))return false;
            int samePath=0;for(NativeAppEvidence.Node other:frame.nodes)if(n.path.equals(other.path))samePath++;
            if(samePath!=1)return false;
            if(i>0&&(!n.description.isEmpty()||!(label?TEXT:VIEW).equals(n.className)
                    ||!(label?"搜索":"").equals(n.text)||!"搜索".equals(n.label)))return false;
        }
        return normalLabel.within(normal)&&toggleLabel.within(toggle);
    }

    /** The retained manual search-entry transition used the ViewSwitcher, not
     * its adjacent searchIcon. The active Session offers that exact entry;
     * every model-issued navigation still needs a fresh search-input contract.
     * The historical manual result is not model execution or query success.
     * The two exact noninteractive descendants supply the original entry label,
     * never a replacement label or the owner's requested product as UI text. */
    private static Page homeSearchEntry(NativeAppEvidence.Frame frame,NativeAppEvidence.Node home,NativeAppEvidence.Node icon,boolean preferSearchIcon){
        String hp="com.xiaomi.shop.plugin.homepage:id/";
        NativeAppEvidence.Node entry=null,pager=null,hint=null,term=null;int entries=0,pagers=0,icons=0,descendants=0;
        for(NativeAppEvidence.Node n:frame.nodes){
            if((hp+"switcher").equals(n.viewId)){entries++;entry=n;}
            if((hp+"home_3_vp").equals(n.viewId)){pagers++;pager=n;}
            if((hp+"searchIcon").equals(n.viewId))icons++;
        }
        if(entries!=1||pagers!=1||icons!=1||!usable(frame,entry)||!usable(frame,pager)
                ||!"android.widget.ViewSwitcher".equals(entry.className)||!"androidx.viewpager.widget.ViewPager".equals(pager.className)
                ||!homeSearchContainer(frame,entry,icon,pager)
                ||!entry.within(pager)||!icon.within(pager)||!adjacent(entry,icon)
                ||!entry.clickable||!entry.text.isEmpty()||!entry.description.isEmpty()
                ||!homeSearchNeutral(entry)||!homeSearchNeutral(icon)||entry.bottom>=home.top)return null;
        for(NativeAppEvidence.Node n:frame.nodes)if(under(n.path,entry.path)){
            descendants++;
            if((entry.path+"/0").equals(n.path))hint=n;
            if((entry.path+"/0/0").equals(n.path))term=n;
        }
        if(descendants!=2||!usable(frame,hint)||!usable(frame,term)
                ||!"android.widget.LinearLayout".equals(hint.className)||!entry.className.equals(hint.parentClass)
                ||!TEXT.equals(term.className)||!hint.className.equals(term.parentClass)
                ||!hint.viewId.isEmpty()||!"com.xiaomi.shop:id/text".equals(term.viewId)
                ||hint.clickable||term.clickable||!homeSearchNeutral(hint)||!homeSearchNeutral(term)
                ||!hint.text.isEmpty()||!term.description.isEmpty()||term.text.trim().isEmpty()
                ||!hint.description.equals("搜索"+term.text)||!hint.within(entry)||!term.within(hint)
                ||!entry.label.equals(ObservedTargetLabels.project(hint.description+" · "+term.text)))return null;
        if(preferSearchIcon&&(!icon.text.isEmpty()||!"搜索".equals(icon.label)))return null;
        NativeAppEvidence.Node chosen=preferSearchIcon?icon:entry;
        Map<String,String> purposes=new LinkedHashMap<String,String>();purposes.put(chosen.id,preferSearchIcon?SEARCH_ICON:"open_search");
        Map<String,Object> proof=map();proof.put("home_marker",home.fact("text"));proof.put("query_entry",entry.fact("description"));
        proof.put("query_entry_original_label",entry.label);proof.put("entry_hint",hint.fact("description"));proof.put("entry_hint_term",term.fact("text"));
        proof.put("adjacent_search_icon",icon.fact("description"));proof.put("adjacent_search_icon_offered",preferSearchIcon);
        if(preferSearchIcon){
            proof.put("navigation_target",icon.fact("description"));proof.put("query_entry_offered",false);
            proof.put("navigation_semantics_device_verified",false);proof.put("fresh_search_contract_required",true);
        }else{
            proof.put("navigation_target",entry.fact("description"));proof.put("query_entry_offered",true);
            proof.put("fresh_search_contract_required",true);proof.put("hint_selects_query",false);
        }
        proof.put("hint_is_owner_query",false);Map<String,Object> facts=map();facts.put(chosen.id,proof);
        return new Page(frame,"home_search",Collections.<String>emptyList(),Collections.singleton(chosen.id),
                Collections.<String,String>emptyMap(),purposes,facts,null,preferSearchIcon);
    }
    private static boolean homeSearchNeutral(NativeAppEvidence.Node n){
        return !n.editable&&!n.scrollable&&n.scrollDirections.isEmpty()&&Boolean.FALSE.equals(n.selected)
                &&Boolean.FALSE.equals(n.checkable)&&Boolean.FALSE.equals(n.checked);
    }
    /** Both retained producers are explicit: compressed service AX uses the
     * pager as parent; the original manual XML retains searchContainer. */
    private static boolean homeSearchContainer(NativeAppEvidence.Frame frame,NativeAppEvidence.Node entry,
            NativeAppEvidence.Node icon,NativeAppEvidence.Node pager){
        if(!parent(entry.path).equals(parent(icon.path))||!entry.parentClass.equals(icon.parentClass))return false;
        if(parent(entry.path).equals(pager.path))return entry.parentClass.equals(pager.className);
        NativeAppEvidence.Node container=null;int count=0;
        for(NativeAppEvidence.Node n:frame.nodes)if("com.xiaomi.shop.plugin.homepage:id/searchContainer".equals(n.viewId)){container=n;count++;}
        return count==1&&usable(frame,container)&&"android.widget.RelativeLayout".equals(container.className)
                &&container.className.equals(entry.parentClass)&&container.path.equals(parent(entry.path))
                &&container.within(pager)&&entry.within(container)&&icon.within(container)
                &&!container.clickable&&container.text.isEmpty()&&container.description.isEmpty()&&homeSearchNeutral(container);
    }

    /** Recognize only the complete installed-version home navigation shell.
     * This supplies no node permission, content claim or automatic action. */
    private static boolean navigationOnlyHome(NativeAppEvidence.Frame frame){
        if(frame.left!=0||frame.top!=0||frame.right!=frame.width||frame.bottom!=frame.height)return false;
        String prefix="com.xiaomi.shop.plugin.homepage:id/";
        Set<String> buttons=new LinkedHashSet<String>(),labels=new LinkedHashSet<String>();int messages=0;
        Set<String> expectedButtons=new LinkedHashSet<String>(java.util.Arrays.asList(
                "main_bottom_home","main_bottom_category","main_bottom_discovery","main_bottom_cart","main_bottom_mine"));
        Set<String> expectedLabels=new LinkedHashSet<String>(java.util.Arrays.asList("首页","分类","服务","购物车","我的"));
        for(NativeAppEvidence.Node n:frame.nodes){
            if(!usable(frame,n)||n.editable||n.scrollable||!n.scrollDirections.isEmpty()
                    ||!Boolean.FALSE.equals(n.checkable)||!Boolean.FALSE.equals(n.checked))return false;
            if((prefix+"msgLayout").equals(n.viewId)){
                if(++messages>1||!"android.widget.RelativeLayout".equals(n.className)||!"消息".equals(n.description)||!n.clickable)return false;
            }else if((prefix+"main_view_nav_bar_text").equals(n.viewId)){
                if(!TEXT.equals(n.className)||n.clickable||!expectedLabels.contains(n.text)||!labels.add(n.text)
                        ||(long)n.top*3<(long)frame.height*2)return false;
            }else if(n.viewId.startsWith(prefix)&&expectedButtons.contains(n.viewId.substring(prefix.length()))){
                if(!"android.view.View".equals(n.className)||!n.clickable||!buttons.add(n.viewId.substring(prefix.length()))
                        ||(long)n.top*3<(long)frame.height*2)return false;
            }else return false;
        }
        return buttons.equals(expectedButtons)&&labels.equals(expectedLabels);
    }

    private static Page unavailable(NativeAppEvidence.Frame frame,String missing){
        return page(frame,"observation_unavailable",missing,null,null);
    }
    private static Page page(NativeAppEvidence.Frame frame,String phase,String missing,NativeAppEvidence.Node card,Quote quote){
        Set<String> clicks=new LinkedHashSet<String>();Map<String,String> purposes=new LinkedHashMap<String,String>();
        Map<String,Object> facts=map();
        if(card!=null){
            NativeAppEvidence.need(usable(frame,card)&&card.clickable,"actual current clickable card required");
            clicks.add(card.id);purposes.put(card.id,"open_exact_product");facts.put(card.id,card.fact("description"));
        }
        return new Page(frame,phase,missing==null?Collections.<String>emptyList():Collections.singletonList(missing),
                clicks,Collections.<String,String>emptyMap(),purposes,facts,quote);
    }
    private static boolean usable(NativeAppEvidence.Frame frame,NativeAppEvidence.Node node){
        return frame.usable(node)&&node.enabled&&!node.password&&!node.text.contains("…")&&!node.description.contains("…");
    }
    private static List<NativeAppEvidence.Node> exactText(NativeAppEvidence.Frame frame,String text){
        List<NativeAppEvidence.Node> result=new ArrayList<NativeAppEvidence.Node>();
        for(NativeAppEvidence.Node n:frame.nodes)if(usable(frame,n)&&TEXT.equals(n.className)&&text.equals(n.text))result.add(n);
        return result;
    }
    private static NativeAppEvidence.Node uniqueText(NativeAppEvidence.Frame frame,String text){
        List<NativeAppEvidence.Node> found=exactText(frame,text);return found.size()==1?found.get(0):null;
    }
    private static NativeAppEvidence.Node clickAncestor(NativeAppEvidence.Frame frame,NativeAppEvidence.Node child){
        NativeAppEvidence.Node best=null;
        for(NativeAppEvidence.Node n:frame.nodes){
            if(!usable(frame,n)||!n.clickable||!child.within(n))continue;
            if(best==null||n.path.length()>best.path.length())best=n;
        }
        return best;
    }
    private static boolean adjacent(NativeAppEvidence.Node left,NativeAppEvidence.Node right){
        return parent(left.path).equals(parent(right.path))&&childIndex(right.path)==childIndex(left.path)+1
                &&left.right<=right.left&&right.left-left.right<=Math.max(left.bottom-left.top,right.bottom-right.top)
                &&Math.min(left.bottom,right.bottom)>Math.max(left.top,right.top);
    }
    private static List<Map<String,Object>> promotions(NativeAppEvidence.Frame frame){
        List<Map<String,Object>> facts=new ArrayList<Map<String,Object>>();
        for(NativeAppEvidence.Node n:frame.nodes)
            if(usable(frame,n)&&TEXT.equals(n.className)&&PROMOTION.matcher(n.text).matches()){
                if(facts.size()==16)break;facts.add(n.fact("text"));
            }
        return facts;
    }
    private static String parent(String path){
        if(path==null)return "";int index=path.lastIndexOf('/');return index<0?"":path.substring(0,index);
    }
    private static boolean under(String path,String ancestor){
        return path!=null&&ancestor!=null&&path.startsWith(ancestor+"/");
    }
    private static String commonParent(String a,String b){
        if(a==null||b==null)return null;String p=parent(a);
        while(!p.isEmpty()){if(under(b,p))return p;p=parent(p);}return null;
    }
    private static int distance(String path,String ancestor){
        if(!under(path,ancestor))return -1;String suffix=path.substring(ancestor.length()+1);
        int count=1;for(int i=0;i<suffix.length();i++)if(suffix.charAt(i)=='/')count++;return count;
    }
    private static int childIndex(String path){
        if(path==null)return -1;try{return Integer.parseInt(path.substring(path.lastIndexOf('/')+1));}
        catch(NumberFormatException invalid){return -1;}
    }
    private static String decimal(String raw){
        NativeAppEvidence.need(raw!=null&&NUMBER.matcher(raw).matches(),"observed decimal amount required");
        BigDecimal value=new BigDecimal(raw);NativeAppEvidence.need(value.signum()>0,"positive observed amount required");
        return value.stripTrailingZeros().toPlainString();
    }
    private static Map<String,Object> map(){return new LinkedHashMap<String,Object>();}
    private static List<Map<String,Object>> immutableFacts(List<Map<String,Object>> source){
        List<Map<String,Object>> result=new ArrayList<Map<String,Object>>();
        for(Map<String,Object> fact:source)result.add(frozen(fact));return Collections.unmodifiableList(result);
    }
    private static Map<String,Object> frozen(Map<String,?> source){
        Map<String,Object> result=map();
        for(Map.Entry<String,?> entry:source.entrySet())result.put(entry.getKey(),freeze(entry.getValue()));
        return Collections.unmodifiableMap(result);
    }
    private static Object freeze(Object value){
        if(value instanceof Map<?,?>){
            Map<String,Object> result=map();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet()){
                NativeAppEvidence.need(e.getKey() instanceof String,"evidence key");
                result.put((String)e.getKey(),freeze(e.getValue()));
            }return Collections.unmodifiableMap(result);
        }
        if(value instanceof Iterable<?>){
            List<Object> result=new ArrayList<Object>();for(Object item:(Iterable<?>)value)result.add(freeze(item));
            return Collections.unmodifiableList(result);
        }
        return value;
    }
}
