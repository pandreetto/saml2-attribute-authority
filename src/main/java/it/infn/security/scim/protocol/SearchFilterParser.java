package it.infn.security.scim.protocol;

import org.parboiled.BaseParser;
import org.parboiled.Parboiled;
import org.parboiled.Rule;
import org.parboiled.annotations.BuildParseTree;
import org.parboiled.parserunners.ReportingParseRunner;
import org.parboiled.support.ParsingResult;
import org.parboiled.support.StringVar;
import org.parboiled.support.Var;

/*
 * TODO check max depth against attacks
 */

@BuildParseTree
public class SearchFilterParser
    extends BaseParser<SearchFilterNode> {

    private char[] sepChars = new char[] { ' ', '\t' };

    Rule start() {
        return Sequence(filter(), EOI);
    }

    Rule filter() {

        StringVar oper = new StringVar();

        return Sequence(
                logicalExpression(),
                ZeroOrMore(Sequence(sep(), FirstOf("and", "or"), oper.set(match()), sep(), logicalExpression()), swap()
                        && push(new SearchFilterNode(pop(), oper.get(), pop()))));
    }

    Rule logicalExpression() {

        Var<Boolean> notExpr = new Var<Boolean>(Boolean.FALSE);

        return FirstOf(
                attributeExpression(),
                valuePath(),
                Sequence(Optional(Sequence("not", sep(), notExpr.set(Boolean.TRUE))), '(', filter(), ')',
                        push(new SearchFilterNode(pop(), notExpr.get().booleanValue()))));
    }

    Rule attributeExpression() {

        StringVar attrPath = new StringVar();
        StringVar oper = new StringVar("pr");
        StringVar value = new StringVar("");

        /*
         * TODO missing check for co sw ew on string
         */
        return Sequence(attributePath(), attrPath.set(match()), sep(),
                FirstOf("pr", Sequence(compOperator(), oper.set(match()), sep(), compValue(), value.set(match()))),
                push(new SearchFilterNode(attrPath.get(), oper.get(), value.get())));
    }

    Rule valuePath() {

        StringVar attrPath = new StringVar();

        return Sequence(attributePath(), attrPath.set(match()), '[', blank(), valueFilter(), blank(), ']',
                push(new SearchFilterNode(attrPath.get(), pop())));

    }

    Rule valueFilter() {

        StringVar oper = new StringVar();

        return Sequence(
                logValExpression(),
                ZeroOrMore(Sequence(sep(), FirstOf("and", "or"), oper.set(match()), sep(), logValExpression()), swap()
                        && push(new SearchFilterNode(pop(), oper.get(), pop()))));
    }

    Rule logValExpression() {

        Var<Boolean> notExpr = new Var<Boolean>(Boolean.FALSE);

        return FirstOf(
                attributeExpression(),
                Sequence(Optional(Sequence("not", sep(), notExpr.set(Boolean.TRUE))), '(', valueFilter(), ')',
                        push(new SearchFilterNode(pop(), notExpr.get().booleanValue()))));
    }

    Rule compValue() {
        return FirstOf("false", "true", "null", number(), string());
    }

    Rule compOperator() {
        return FirstOf("eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le");
    }

    Rule attributePath() {
        /*
         * TODO missing uri
         */
        return Sequence(attributeName(), Optional(subAttribute()));
    }

    Rule attributeName() {
        return Sequence(alpha(), ZeroOrMore(nameChar()));
    }

    Rule number() {
        return OneOrMore(digit());
    }

    Rule string() {
        return Sequence('"', OneOrMore(nameChar()), '"');
    }

    Rule nameChar() {
        return FirstOf('-', '_', alpha(), digit());
    }

    Rule subAttribute() {
        return Sequence(".", attributeName());
    }

    Rule alpha() {
        return FirstOf(CharRange('a', 'z'), CharRange('A', 'Z'));
    }

    Rule digit() {
        return CharRange('0', '9');
    }

    Rule blank() {
        return ZeroOrMore(AnyOf(sepChars));
    }

    Rule sep() {
        return OneOrMore(AnyOf(sepChars));
    }

    public static SearchFilterNode parse(String input) {

        SearchFilterParser parser = Parboiled.createParser(SearchFilterParser.class);
        @SuppressWarnings({ "rawtypes", "unchecked" })
        ParsingResult<SearchFilterNode> result = new ReportingParseRunner(parser.start()).run(input);
        if (result.matched) {
            return result.parseTreeRoot.getValue();
        }

        return null;
    }

}
