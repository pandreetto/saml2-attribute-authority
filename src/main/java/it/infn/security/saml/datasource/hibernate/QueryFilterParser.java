package it.infn.security.saml.datasource.hibernate;

import java.util.HashMap;

import it.infn.security.saml.datasource.DataSourceException;

import org.parboiled.BaseParser;
import org.parboiled.Parboiled;
import org.parboiled.Rule;
import org.parboiled.annotations.BuildParseTree;
import org.parboiled.parserunners.ReportingParseRunner;
import org.parboiled.support.ParsingResult;
import org.parboiled.support.StringVar;
import org.parboiled.support.Var;

@BuildParseTree
public class QueryFilterParser
    extends BaseParser<QueryNode> {

    private char[] sepChars = new char[] { ' ', '\t' };

    Rule start() {
        return Sequence(filter(), EOI);
    }

    Rule filter() {

        StringVar oper = new StringVar();

        return Sequence(
                logicalExpression(),
                ZeroOrMore(Sequence(sep(), FirstOf("and", "or"), oper.set(match()), sep(), logicalExpression()), swap()
                        && push(new QueryNode(pop(), oper.get(), pop()))));
    }

    Rule logicalExpression() {

        Var<Boolean> notExpr = new Var<Boolean>(Boolean.FALSE);

        return FirstOf(
                attributeExpression(),
                valuePath(),
                Sequence(Optional(Sequence("not", sep(), notExpr.set(Boolean.TRUE))), '(', filter(), ')',
                        push(new QueryNode(pop(), notExpr.get().booleanValue()))));
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
                push(new QueryNode(attrPath.get(), oper.get(), value.get())));
    }

    Rule valuePath() {

        StringVar attrPath = new StringVar();

        return Sequence(attributePath(), attrPath.set(match()), '[', valueFilter(), ']',
                push(new QueryNode(attrPath.get(), pop())));

    }

    Rule valueFilter() {

        StringVar oper = new StringVar();

        return Sequence(
                logValExpression(),
                ZeroOrMore(Sequence(sep(), FirstOf("and", "or"), oper.set(match()), sep(), logValExpression()), swap()
                        && push(new QueryNode(pop(), oper.get(), pop()))));
    }

    Rule logValExpression() {

        Var<Boolean> notExpr = new Var<Boolean>(Boolean.FALSE);

        return FirstOf(
                attributeExpression(),
                Sequence(Optional(Sequence("not", sep(), notExpr.set(Boolean.TRUE))), '(', valueFilter(), ')',
                        push(new QueryNode(pop(), notExpr.get().booleanValue()))));
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

    Rule sep() {
        return AnyOf(sepChars);
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static QueryNode parse(String input)
        throws DataSourceException {

        QueryFilterParser parser = Parboiled.createParser(QueryFilterParser.class);
        ParsingResult<QueryNode> result = new ReportingParseRunner(parser.start()).run(input);
        if (result.matched) {

            QueryNode rootNode = result.parseTreeRoot.getValue();
            if (rootNode != null) {
                return rootNode;
            }

        }

        throw new DataSourceException("Cannot parse query filter");
    }

    public static void main(String args[]) {

        try {
            QueryNode rootNode = parse(args[0]);
            System.out.println(rootNode.getFormatString());

            HashMap<String, Object> params = new HashMap<String, Object>();
            rootNode.fillinParameters(params);
            for (String key : params.keySet()) {
                System.out.println(key + " = " + params.get(key).toString());
            }
        } catch (Throwable th) {
            th.printStackTrace();
        }

    }
}
