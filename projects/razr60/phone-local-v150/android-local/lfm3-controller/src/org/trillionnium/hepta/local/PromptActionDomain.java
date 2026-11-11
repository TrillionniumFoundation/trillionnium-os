package org.trillionnium.hepta.local;

import java.util.Set;
import java.util.Map;

/** Admission protects every currently observed action target before optional text.
 * This adds no permission: repeat, signature, freshness and actual-action gates
 * still run, and a raw isScrollable flag never grants a direction.
 */
public final class PromptActionDomain {
    private PromptActionDomain() {}
    public static boolean eligible(String observedPackage,String nodePackage,boolean enabled,boolean password){
        if(observedPackage==null||nodePackage==null)throw new IllegalArgumentException("observed package facts required");
        return observedPackage.equals(nodePackage)&&enabled&&!password;
    }
    /** The ordinary controller has no image input: a resource ID, class, bounds
     * or clickable flag cannot explain an otherwise unnamed icon. Inspect only
     * the actual text exposed in its existing projection, without inventing a
     * label or using a projection-added ellipsis as evidence of visible text.
     * This is a click restriction only; empty editable/scroll targets survive.
     */
    public static boolean textOnlyClickLabel(String observedLabel){
        if(observedLabel==null)return false;
        String projected=ObservedTargetLabels.project(observedLabel);
        int end=projected.length();
        if(observedLabel.length()>ObservedTargetLabels.PROJECTION_UTF16_LIMIT)end--;
        for(int at=0;at<end;){
            int code=projected.codePointAt(at);at+=Character.charCount(code);
            if(Character.isWhitespace(code)||Character.isSpaceChar(code)
                    ||code==0x115f||code==0x1160||code==0x3164||code==0xffa0||code==0x2800)continue;
            switch(Character.getType(code)){
                case Character.UPPERCASE_LETTER:case Character.LOWERCASE_LETTER:
                case Character.TITLECASE_LETTER:case Character.MODIFIER_LETTER:case Character.OTHER_LETTER:
                case Character.DECIMAL_DIGIT_NUMBER:case Character.LETTER_NUMBER:case Character.OTHER_NUMBER:
                case Character.CONNECTOR_PUNCTUATION:case Character.DASH_PUNCTUATION:
                case Character.START_PUNCTUATION:case Character.END_PUNCTUATION:
                case Character.INITIAL_QUOTE_PUNCTUATION:case Character.FINAL_QUOTE_PUNCTUATION:
                case Character.OTHER_PUNCTUATION:case Character.MATH_SYMBOL:case Character.CURRENCY_SYMBOL:
                case Character.MODIFIER_SYMBOL:case Character.OTHER_SYMBOL:return true;
                default:break; // Control/format/marks/surrogates/private-use/unassigned add no visible label.
            }
        }
        return false;
    }
    /** Match the existing own-text/description/descendant selection exactly.
     * Derived labels admit only original child characters in the current prefix,
     * never the collector's artificial separators or truncation punctuation.
     */
    public static boolean textOnlyClickLabel(String text,String description,ObservedChildText.Result childText){
        if(text!=null&&!text.trim().isEmpty())return textOnlyClickLabel(text);
        if(description!=null&&!description.trim().isEmpty())return textOnlyClickLabel(description);
        return childText!=null&&textOnlyClickLabel(childText.observedPrefix(ObservedTargetLabels.PROJECTION_UTF16_LIMIT));
    }
    /** Independent dispatch eligibility, even when a model bypasses the GBNF.
     * The immutable set is exactly the final click domain used for that prompt.
     * Labels remain exact observation data; this never resolves or rewrites one.
     */
    public static void requireTextOnlyClick(ActionDecision action,ObservedTargetLabels targets,Set<String> clicks)
            throws ActionDecision.InvalidActionException{
        if(action==null)throw new ActionDecision.InvalidActionException("missing text-only decision");
        if(!"click".equals(action.action))return;
        if(targets==null||clicks==null||!clicks.contains(action.nodeId)
                ||!targets.matches(action.observationId,action.packageName,action.nodeId,action.nodeLabel))
            throw new ActionDecision.InvalidActionException("click target lacks a permitted observed text label in this prompt");
    }
    public static boolean requiresRetention(String observedPackage,String nodePackage,
            boolean enabled,boolean password,boolean clickable,boolean editable,ObservedScrollActions scrollActions){
        if(observedPackage==null||nodePackage==null||scrollActions==null)throw new IllegalArgumentException("observed capability facts required");
        return eligible(observedPackage,nodePackage,enabled,password)&&(clickable||editable||scrollActions.hasAny());
    }
    /** Describe the same post-policy sets supplied to DecisionGrammar, never raw widget flags. */
    public static String promptFlags(String nodeId,boolean focused,Set<String> clicks,Set<String> edits,
            Map<String,ObservedScrollActions> scrolls){
        if(nodeId==null||clicks==null||edits==null||scrolls==null)throw new IllegalArgumentException("actual action domain required");
        ObservedScrollActions directions=scrolls.get(nodeId);
        return (clicks.contains(nodeId)?"c":"")+(edits.contains(nodeId)?"t":"")
                +(directions!=null&&directions.hasAny()?"s":"")+(focused?"f":"");
    }
    public static void requireComplete(Set<String> required,Set<String> shown){
        if(required==null||shown==null||!shown.containsAll(required))
            throw new IllegalStateException("当前可操作节点未完整提供，未请求模型动作");
    }
}
