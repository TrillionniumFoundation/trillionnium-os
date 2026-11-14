package org.trillionnium.hepta.local;

import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A bounded, immutable OWNER arithmetic goal. This class grants no tool and
 * cannot turn a model proposal or observed screen text into a different goal. */
public final class CalculatorGoalContract {
    public static final String SCHEMA="hepta.calculator-owner-goal.v1";
    public static final String PACKAGE="com.motorola.cn.calculator";
    public static final int MAX_EXPRESSION_UTF16=96,MAX_LITERAL_DIGITS=32;
    public static final int MAX_VALUE_DIGITS=64,MAX_BINARY_OPERATORS=24,MAX_DEPTH=8;
    private static final String PREFIX="(?:请)?打开(?:\\s*Moto\\s*)?计算器"
            +"(?:（com\\.motorola\\.cn\\.calculator）|\\(com\\.motorola\\.cn\\.calculator\\))?[，,]\\s*";
    private static final Pattern OWNER=Pattern.compile("^\\s*"+PREFIX
            +"(?:在当前主输入区)?计算\\s*([^\\r\\n]+?)[，,]\\s*"
            +"确认(?:当前结果框|屏幕)显示计算结果后结束任务[。.]\\s*$");

    public final String ownerSha256,contractSha256,rawExpression,canonicalExpression;
    public final String expressionSha256,expectedResult,expectedResultSha256;
    public final String recognition="literal_integer_calculation_current_result.v1";
    private final Expression expression;

    private CalculatorGoalContract(String owner,String raw,Expression parsed){
        ownerSha256=ObservedImeEnter.hash(owner);rawExpression=raw;expression=parsed;
        canonicalExpression=parsed.canonical;expressionSha256=ObservedImeEnter.hash(raw);
        expectedResult=parsed.value.toString();expectedResultSha256=ObservedImeEnter.hash(expectedResult);
        contractSha256=ObservedImeEnter.hash(SCHEMA+"\n"+ownerSha256+"\n"+PACKAGE+"\n"
                +recognition+"\n"+expressionSha256+"\n"+canonicalExpression+"\n"+expectedResultSha256);
    }

    /** Unsupported or partly consumed goals return null. A foreign authorization
     * is an error, not an opportunity to parse a new model-selected OWNER. */
    public static CalculatorGoalContract parse(String owner,TaskAuthorization authorization){
        if(authorization==null)throw new IllegalArgumentException("immutable OWNER authorization required");
        authorization.requireOwner(owner);
        Matcher match=OWNER.matcher(owner);
        if(!match.matches())return null;
        String raw=match.group(1);Expression parsed=parseExpression(raw);
        if(parsed==null||parsed.binaryOperators==0)return null;
        return new CalculatorGoalContract(owner,raw,parsed);
    }

    /** This map is archival evidence, not an instruction to emit the expected
     * answer into an editable field or a new tool/prompt capability. */
    public Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema",SCHEMA);out.put("source","immutable_owner_contract");
        out.put("owner_sha256",ownerSha256);out.put("contract_sha256",contractSha256);
        out.put("target_package",PACKAGE);out.put("recognition",recognition);
        out.put("expression_raw",rawExpression);out.put("expression_sha256",expressionSha256);
        out.put("canonical_expression",canonicalExpression);out.put("binary_operators",expression.binaryOperators);
        out.put("expected_integer",expectedResult);out.put("expected_integer_sha256",expectedResultSha256);
        out.put("arithmetic","bounded_exact_big_integer_add_subtract_multiply");
        out.put("model_may_change_goal",false);out.put("grants_tool_authority",false);
        return Collections.unmodifiableMap(out);
    }

    /** An exact AST form is used instead of mere numerical equivalence: a current
     * field containing only the answer cannot impersonate the requested formula. */
    public boolean matchesFormula(String completeText){
        Expression observed=parseExpression(completeText);
        return observed!=null&&canonicalExpression.equals(observed.canonical);
    }

    public static final class Expression {
        public final String canonical;public final BigInteger value;public final int binaryOperators;
        private Expression(Term term,int operators){canonical=term.canonical;value=term.value;binaryOperators=operators;}
    }
    private static final class Term {
        final String canonical;final BigInteger value;
        Term(String canonical,BigInteger value){
            if(value.abs().toString().length()>MAX_VALUE_DIGITS)throw invalid();
            this.canonical=canonical;this.value=value;
        }
    }

    /** ASCII decimal integers, explicit operator aliases, unary +/-, and bounded
     * parentheses only. No NFKC, eval, decimal rounding, variables or digit scan. */
    public static Expression parseExpression(String raw){
        if(raw==null||raw.isEmpty()||raw.length()>MAX_EXPRESSION_UTF16)return null;
        try{
            Parser parser=new Parser(raw);Term value=parser.sum(0);parser.spaces();
            if(parser.at!=raw.length())return null;
            return new Expression(value,parser.operators);
        }catch(IllegalArgumentException unsupported){return null;}
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("unsupported bounded integer expression");}
    private static final class Parser {
        final String input;int at,operators;
        Parser(String input){this.input=input;}
        void spaces(){while(at<input.length()&&input.charAt(at)==' ')at++;}
        boolean take(String token){spaces();if(input.startsWith(token,at)){at+=token.length();return true;}return false;}
        String addOperator(){
            for(String token:new String[]{"加上","加","+","＋"})if(take(token))return "+";
            for(String token:new String[]{"减去","减","-","−","－"})if(take(token))return "-";
            return null;
        }
        boolean multiply(){return take("乘以")||take("乘")||take("×")||take("*");}
        void counted(){if(++operators>MAX_BINARY_OPERATORS)throw invalid();}
        Term sum(int depth){
            Term value=product(depth);
            while(true){String op=addOperator();if(op==null)return value;counted();Term right=product(depth);
                value=new Term("("+value.canonical+op+right.canonical+")",
                        "+".equals(op)?value.value.add(right.value):value.value.subtract(right.value));}
        }
        Term product(int depth){
            Term value=factor(depth);
            while(multiply()){counted();Term right=factor(depth);
                value=new Term("("+value.canonical+"*"+right.canonical+")",value.value.multiply(right.value));}
            return value;
        }
        Term factor(int depth){
            if(depth>MAX_DEPTH)throw invalid();spaces();
            if(take("+")||take("＋"))return factor(depth+1);
            if(take("-")||take("−")||take("－")){
                Term value=factor(depth+1);return new Term("(-"+value.canonical+")",value.value.negate());
            }
            if(take("(")){Term value=sum(depth+1);if(!take(")"))throw invalid();return value;}
            if(take("（")){Term value=sum(depth+1);if(!take("）"))throw invalid();return value;}
            spaces();int start=at;
            while(at<input.length()&&input.charAt(at)>='0'&&input.charAt(at)<='9')at++;
            if(at==start||at-start>MAX_LITERAL_DIGITS)throw invalid();
            BigInteger value=new BigInteger(input.substring(start,at));return new Term(value.toString(),value);
        }
    }
}
